"""Conditional source-qualified FName string value, diagnostic opt-in only.

The ordinary Property90/Structured88/Archive50 chain reaches the recovered
name grammar only when its actual Archive/PackageMap override agrees. That
override is not observed here. No property, actor, account, timing or permanent
configuration mapping is inferred. No networking or process access occurs.
"""
from dataclasses import dataclass
import re

from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.replication.legacy_ds_actor_content import ActorContentBlock
from dfserver.replication.legacy_ds_scalar_serializers import SHIPPING_SHA256

FNAME_TABLE_RVA, FNAME_LEAF_RVA, GENERIC_SERIALIZER_RVA = 0x15a86ce0, 0x286bfc0, 0x10e5ce20
SPEC_SHA256 = 'c12e200f8fdc4b0bd5ae88e15032579f6ec031018f73cf85f86b33383c07f642'
MAX_LABEL_BYTES, MAX_VALUE_BITS = 96, 65 + 8 * 97


@dataclass(frozen=True)
class NativeFNameStringDiagnosticBinding:
    client_sha256: str
    property_vtable_rva: int
    scalar_leaf_target_rva: int
    serializer_target_rva: int
    source_spec_sha256: str
    actual_package_map_override_observed: bool = False


def _qualify(binding):
    if (type(binding) is not NativeFNameStringDiagnosticBinding
            or binding.client_sha256 != SHIPPING_SHA256
            or type(binding.property_vtable_rva) is not int or binding.property_vtable_rva != FNAME_TABLE_RVA
            or type(binding.scalar_leaf_target_rva) is not int or binding.scalar_leaf_target_rva != FNAME_LEAF_RVA
            or type(binding.serializer_target_rva) is not int or binding.serializer_target_rva != GENERIC_SERIALIZER_RVA
            or binding.source_spec_sha256 != SPEC_SHA256
            or binding.actual_package_map_override_observed is not False):
        raise ValueError('Exact conditional diagnostic FName binding required')


def write_diagnostic_fname_string_value(writer, text, number, *, binding, diagnostic_probe=False):
    """Append a nonhardcoded ASCII FString+original Number, without alignment.

    Default false leaves the writer untouched and does not qualify a binding.
    The explicit opt-in permits a field-readback experiment; it never asserts
    that an unobserved runtime PackageMap accepts this recovered base grammar.
    """
    if type(diagnostic_probe) is not bool:
        raise ValueError('Diagnostic FName probe must be an explicit boolean')
    if not diagnostic_probe:
        return 0
    if type(writer) is not BitWriter:
        raise ValueError('A native bit writer is required')
    _qualify(binding)
    if (type(text) is not str or re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', text) is None
            or type(number) is not int or not 0 <= number <= 0xffffffff):
        raise ValueError('Bounded ASCII configuration label and original uint32 Number required')
    payload = text.encode('ascii') + b'\0'
    staged = BitWriter(maximum_bits=MAX_VALUE_BITS)
    staged.write_bool(False)
    staged.write_bytes(len(payload).to_bytes(4, 'little', signed=True))
    staged.write_bytes(payload)
    staged.write_bytes(number.to_bytes(4, 'little'))
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def build_diagnostic_fname_content(*, handle, text, number, binding, diagnostic_probe=False):
    """One ordinary non-array/debug property: option0, handle, value, terminal0.

    This emits no ClassNetCache/RPC envelope or presence bit. Source-qualified
    caller chooses the property handle and current owning Actor channel.
    """
    if type(diagnostic_probe) is not bool:
        raise ValueError('Diagnostic FName probe must be an explicit boolean')
    if not diagnostic_probe:
        return None
    if type(handle) is not int or not 1 <= handle <= 65535:
        raise ValueError('An explicit ordinary property handle required')
    writer = BitWriter(maximum_bits=1 + 80 + MAX_VALUE_BITS)
    writer.write_bool(False)
    writer.write_packed_int(handle)
    write_diagnostic_fname_string_value(writer, text, number, binding=binding, diagnostic_probe=True)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)
