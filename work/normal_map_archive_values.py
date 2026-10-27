"""Pure values for the proven normal FNetBitReader FName/FText overrides.

No class/property handle, actor reference, localized text row, or gameplay state
is inferred. Source callers must retain original cooked FName base/Number.
"""
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'outputs/df-local-server'))
from dfserver.legacy_ds_bit_archive import BitReader, BitWriter

CONTRACT_PATH = 'work/evidence/model-init-chain-20261018/native-map-normal-archive-name-text-contract-v1.json'
CONTRACT_SHA256 = '667c2ba4b67e764fadae6b6947a04b2089771bb43fc2436cfa9a15a3ae29449f'
CLIENT_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
MAX_NAME_BYTES = 256
MAX_KEY_BYTES = 1024
VECTOR_CONTRACT_PATH = 'work/evidence/model-init-chain-20261018/native-map-plain-vector-value-contract-v1.json'
VECTOR_CONTRACT_SHA256 = 'fd74fc9ab3aeb5def87ba704b8613d9654b47a3091ef9fa3a9d2c58e29314ac6'


@dataclass(frozen=True)
class NativeNormalArchiveBinding:
    client_sha256: str
    contract_sha256: str
    net_reader_vtable_rva: int
    archive_name_slot_rva: int
    archive_text_slot_rva: int


@dataclass(frozen=True)
class NativeName:
    base_name: str
    original_number: int

    @property
    def display_name(self):
        return self.base_name + (('_'+str(self.original_number-1)) if self.original_number else '')


@dataclass(frozen=True)
class NativeStringTableText:
    flags: int
    table_id: NativeName
    key: str


@dataclass(frozen=True)
class NativePlainVectorBinding:
    client_sha256: str
    contract_sha256: str
    property_serializer_rva: int
    struct_getter_rva: int
    cppops_vtable_rva: int
    netserialize_body_rva: int


def qualify_contract(root=ROOT):
    root = Path(root).resolve()
    raw = (root/CONTRACT_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CONTRACT_SHA256:
        raise ValueError('Exact concrete normal archive contract required')
    contract = json.loads(raw)
    if (contract['client_sha256'] != CLIENT_SHA256 or contract['process_access'] is not False
            or contract['client_launched'] is not False):
        raise ValueError('Offline client source identity differs')
    for pin in contract['sources']:
        path = (root/pin['path']).resolve()
        if (not path.is_relative_to(root/'work/evidence')
                or hashlib.sha256(path.read_bytes()).hexdigest() != pin['sha256']):
            raise ValueError('Concrete normal archive source changed')
    return NativeNormalArchiveBinding(CLIENT_SHA256, CONTRACT_SHA256,
                                      0x16559d98, 0x10cf7080, 0x10b3de50)


def source_pins(root=ROOT):
    qualify_contract(root)
    contract = json.loads((Path(root)/CONTRACT_PATH).read_bytes())
    return [dict(path=CONTRACT_PATH, sha256=CONTRACT_SHA256), *contract['sources']]


def qualify_vector_contract(root=ROOT):
    root = Path(root).resolve()
    raw = (root/VECTOR_CONTRACT_PATH).read_bytes()
    if hashlib.sha256(raw).hexdigest() != VECTOR_CONTRACT_SHA256:
        raise ValueError('The exact plain Vector CppOps source is required')
    contract = json.loads(raw)
    for relative, digest in contract['sources'].items():
        path = (root/relative).resolve()
        if not path.is_relative_to(root/'work/evidence') or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('The plain Vector source changed')
    return NativePlainVectorBinding(CLIENT_SHA256, VECTOR_CONTRACT_SHA256,
        0x10e8ee50, 0x10ed3750, 0x1ab5b588, 0x13b4a70)


def vector_source_pins(root=ROOT):
    qualify_vector_contract(root)
    contract = json.loads((Path(root)/VECTOR_CONTRACT_PATH).read_bytes())
    return dict({VECTOR_CONTRACT_PATH: VECTOR_CONTRACT_SHA256}, **contract['sources'])


def _vector_binding(binding, no_byteswap):
    if (type(binding) is not NativePlainVectorBinding or no_byteswap is not True
            or binding != NativePlainVectorBinding(CLIENT_SHA256, VECTOR_CONTRACT_SHA256,
                0x10e8ee50, 0x10ed3750, 0x1ab5b588, 0x13b4a70)):
        raise ValueError('Exact plain Vector binding and no-byteswap profile required')


def write_plain_vector(writer, value, *, binding, no_byteswap):
    _vector_binding(binding, no_byteswap)
    if (type(writer) is not BitWriter or type(value) is not tuple or len(value) != 3
            or any(type(n) not in (int, float) or not math.isfinite(n) for n in value)):
        raise ValueError('Three finite original plain Vector coordinates required')
    try:
        raw = struct.pack('<3f', *value)
    except (OverflowError, struct.error) as exc:
        raise ValueError('Plain Vector value exceeds native float32') from exc
    writer.write_bytes(raw)
    return 96


def read_plain_vector(reader, *, binding, no_byteswap):
    _vector_binding(binding, no_byteswap)
    if type(reader) is not BitReader:
        raise ValueError('Native bit reader required')
    result = struct.unpack('<3f', reader.read_bytes(12))
    if any(not math.isfinite(n) for n in result):
        raise ValueError('Non-finite plain Vector is outside this source codec')
    return result


def _binding(binding):
    if (type(binding) is not NativeNormalArchiveBinding
            or binding != NativeNormalArchiveBinding(CLIENT_SHA256, CONTRACT_SHA256,
                                                       0x16559d98, 0x10cf7080, 0x10b3de50)):
        raise ValueError('Concrete normal network archive binding required')


def _ascii_string(value, maximum):
    if type(value) is not str or '\0' in value:
        raise ValueError('Bounded original ASCII string required')
    try:
        raw = value.encode('ascii')
    except UnicodeEncodeError as exc:
        raise ValueError('This value codec only qualifies ASCII source strings') from exc
    if len(raw) > maximum:
        raise ValueError('Source string exceeds local codec bound')
    return raw+b'\0'


def _name(value):
    if (type(value) is not NativeName or type(value.original_number) is not int
            or not 0 <= value.original_number <= 0xffffffff):
        raise ValueError('Original FName base and uint32 Number required')
    return _ascii_string(value.base_name, MAX_NAME_BYTES)


def _write_fstring(writer, payload):
    writer.write_bytes(len(payload).to_bytes(4, 'little', signed=True))
    writer.write_bytes(payload)


def _write_name(writer, value, payload):
    writer.write_bool(False)
    _write_fstring(writer, payload)
    writer.write_bytes(value.original_number.to_bytes(4, 'little'))


def write_name(writer, value, *, binding):
    _binding(binding)
    if type(writer) is not BitWriter:
        raise ValueError('Native bit writer required')
    payload = _name(value)
    staged = BitWriter()
    _write_name(staged, value, payload)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def write_string_table_text(writer, value, *, binding):
    _binding(binding)
    if type(writer) is not BitWriter:
        raise ValueError('Native bit writer required')
    if type(value) is not NativeStringTableText or type(value.flags) is not int or value.flags != 0:
        raise ValueError('Only source StringTableEntry with flags0 is qualified here')
    table = _name(value.table_id)
    key = _ascii_string(value.key, MAX_KEY_BYTES)
    staged = BitWriter()
    staged.write_bits(0, 32)
    staged.write_bits(11, 8)
    _write_name(staged, value.table_id, table)
    _write_fstring(staged, key)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def _read_fstring(reader, maximum):
    count = int.from_bytes(reader.read_bytes(4), 'little', signed=True)
    if not 1 <= count <= maximum+1:
        raise ValueError('Unsupported or overbound FString count')
    raw = reader.read_bytes(count)
    if raw[-1:] != b'\0' or b'\0' in raw[:-1]:
        raise ValueError('Native FString terminator differs')
    try:
        return raw[:-1].decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError('Only bounded source ASCII FString supported') from exc


def read_name(reader, *, binding):
    _binding(binding)
    if type(reader) is not BitReader:
        raise ValueError('Native bit reader required')
    if reader.read_bool():
        raise ValueError('Hardcoded FName indices are outside this source codec')
    name = _read_fstring(reader, MAX_NAME_BYTES)
    number = int.from_bytes(reader.read_bytes(4), 'little')
    return NativeName(name, number)


def read_string_table_text(reader, *, binding):
    _binding(binding)
    if type(reader) is not BitReader:
        raise ValueError('Native bit reader required')
    flags = reader.read_bits(32)
    history = reader.read_bits(8)
    if flags != 0 or history != 11:
        raise ValueError('Only source flags0/StringTableEntry history11 supported')
    table_id = read_name(reader, binding=binding)
    key = _read_fstring(reader, MAX_KEY_BYTES)
    return NativeStringTableText(flags, table_id, key)
