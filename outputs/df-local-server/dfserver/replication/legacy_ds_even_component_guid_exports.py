"""Opt-in, consumer-compatible even component Name/Outer exports.

This independent pure codec does not modify the legacy odd-only exporter.
The native consumer accepts a GUID path with flags3 as Outer + FString:
bit1 alters registration/lookup policy but adds no wire suffix. This is an
explicit compatibility choice, not verified equivalence to the current
normal PackageMap.v310 sender. The caller must qualify the current local
namespace, existing Pawn Outer, typed component Name/Outer and NameStable
predicate. No GUID allocation, resolver, native call or socket is present.
"""
from dataclasses import dataclass, field

from dfserver.legacy_ds_bit_archive import BitReader, BitWriter, UINT32_MAX
from dfserver.legacy_ds_control_fields import decode_string, encode_string
from dfserver.legacy_ds_guid_exports import GuidExportLimits, DEFAULT_LIMITS


class UnsupportedEvenComponentExport(ValueError):
    pass


@dataclass(frozen=True)
class ExistingPawnOuterReference:
    guid: int


@dataclass(frozen=True)
class EvenComponentExportNode:
    guid: int
    name: str
    outer: ExistingPawnOuterReference


@dataclass(frozen=True)
class EvenComponentBinding:
    guid: int
    name: str
    outer_pawn_guid: int


def _even_guid(value):
    return type(value) is int and 2 <= value <= UINT32_MAX and not value & 1


@dataclass(frozen=True)
class EvenComponentExportProfile:
    current_pawn_guid: int
    components: tuple[EvenComponentBinding, ...]
    current_pawn_existing_and_resolved: bool
    current_name_stable_qualified: bool
    current_typed_name_outer_qualified: bool
    current_local_actor_namespace_owner_qualified: bool
    ordinary_game_package_map_reference_qualified: bool
    normal_connection: bool
    no_checksum_contract_qualified: bool
    source_owner_check: object = field(repr=False)

    @property
    def compatibility_choice(self):
        return True

    @property
    def normal_sender_equivalence_verified(self):
        return False

    def __post_init__(self):
        required = (
            self.current_pawn_existing_and_resolved,
            self.current_name_stable_qualified,
            self.current_typed_name_outer_qualified,
            self.current_local_actor_namespace_owner_qualified,
            self.ordinary_game_package_map_reference_qualified,
            self.normal_connection, self.no_checksum_contract_qualified,
        )
        if (not _even_guid(self.current_pawn_guid) or type(self.components) is not tuple or
                not 1 <= len(self.components) <= 8 or any(v is not True for v in required) or
                not callable(self.source_owner_check)):
            raise UnsupportedEvenComponentExport('current_local_component_export_qualification_required')
        guids, names = set(), set()
        for b in self.components:
            if (type(b) is not EvenComponentBinding or not _even_guid(b.guid) or
                    b.guid == self.current_pawn_guid or type(b.outer_pawn_guid) is not int or
                    b.outer_pawn_guid != self.current_pawn_guid or type(b.name) is not str or
                    not 1 <= len(b.name) <= 256 or
                    any(c in b.name for c in ('\0', '\r', '\n', '/', '\\', ':', '.')) or
                    b.guid in guids or b.name in names):
                raise UnsupportedEvenComponentExport('distinct_current_even_component_name_outer_bindings_required')
            guids.add(b.guid)
            names.add(b.name)


def _profile(enabled, profile):
    if type(enabled) is not bool:
        raise UnsupportedEvenComponentExport('explicit_even_export_boolean_required')
    if not enabled:
        raise UnsupportedEvenComponentExport('even_component_export_default_off')
    if type(profile) is not EvenComponentExportProfile:
        raise UnsupportedEvenComponentExport('exact_even_component_export_profile_required')
    profile.__post_init__()
    return profile


def _facts(profile):
    return (profile.current_pawn_guid,
            tuple((b.guid, b.name, b.outer_pawn_guid) for b in profile.components),
            profile.current_pawn_existing_and_resolved,
            profile.current_name_stable_qualified, profile.current_typed_name_outer_qualified,
            profile.current_local_actor_namespace_owner_qualified,
            profile.ordinary_game_package_map_reference_qualified, profile.normal_connection,
            profile.no_checksum_contract_qualified, profile.source_owner_check)


def _recheck(profile, original):
    profile.__post_init__()
    if profile.source_owner_check is not original[-1] or _facts(profile) != original:
        raise UnsupportedEvenComponentExport('even_export_profile_changed')
    try:
        current = profile.source_owner_check()
    except Exception:
        raise UnsupportedEvenComponentExport('even_export_source_owner_closure_refused') from None
    profile.__post_init__()
    if current is not True or profile.source_owner_check is not original[-1] or _facts(profile) != original:
        raise UnsupportedEvenComponentExport('even_export_source_owner_closure_changed')


def _limits(limits):
    if type(limits) is not GuidExportLimits:
        raise ValueError('exact_guid_export_limits_required')
    limits.__post_init__()


def _bound_count(count, profile, limits):
    if not 1 <= count <= min(limits.max_exports, len(profile.components)):
        raise UnsupportedEvenComponentExport('even_export_count_outside_explicit_profile')
    if limits.max_depth < 1 or count * 2 > limits.max_nodes:
        raise ValueError('even_export_depth_or_node_bound')


def write_even_component_guid_exports(writer, exports, *, enabled=False, profile=None,
                                      limits=DEFAULT_LIMITS, force_unicode=False):
    """Atomically append false/count32 + each GUID/flags3/Pawn/flags0/Name.

    The reference-only Pawn Outer has no Name/Outer suffix. Neither node
    has a checksum. Local profile facts and source/owner closure must hold
    before and after staging. Qualification is supplied by the caller.
    """
    profile = _profile(enabled, profile)
    if not isinstance(writer, BitWriter):
        raise ValueError('native_bit_writer_required')
    _limits(limits)
    if type(exports) is not tuple or type(force_unicode) is not bool:
        raise ValueError('explicit_export_tuple_and_unicode_boolean_required')
    _bound_count(len(exports), profile, limits)
    facts = _facts(profile)
    _recheck(profile, facts)
    bindings = {b.guid: b for b in profile.components}
    staged = BitWriter(maximum_bits=limits.max_bytes * 8)
    staged.write_bool(False)
    staged.write_bits(len(exports), 32)
    seen = set()
    for node in exports:
        binding = bindings.get(node.guid) if type(node) is EvenComponentExportNode and type(node.guid) is int else None
        if (binding is None or type(node.name) is not str or node.name != binding.name or
                type(node.outer) is not ExistingPawnOuterReference or
                type(node.outer.guid) is not int or node.outer.guid != binding.outer_pawn_guid or
                node.guid in seen):
            raise UnsupportedEvenComponentExport('node_differs_from_current_even_component_profile')
        seen.add(node.guid)
        staged.write_packed_int(node.guid)
        staged.write_bits(3, 8)
        staged.write_packed_int(node.outer.guid)
        staged.write_bits(0, 8)
        staged.write_bytes(encode_string(node.name, force_unicode=force_unicode,
                                        max_units=limits.max_path_units))
    _recheck(profile, facts)
    writer.write_payload(staged.to_bytes(), staged.bit_count)
    return staged.bit_count


def read_even_component_guid_exports(reader, *, enabled=False, profile=None, limits=DEFAULT_LIMITS):
    """Parse the same strict compatibility subset without resolving objects.

    A failed parse or closure leaves the original cursor unchanged.
    Following content remains unread. Only flags3 component paths and the
    exact flags0 current Pawn reference are accepted by this local policy.
    """
    profile = _profile(enabled, profile)
    if not isinstance(reader, BitReader):
        raise ValueError('native_bit_reader_required')
    _limits(limits)
    facts = _facts(profile)
    _recheck(profile, facts)
    start = reader.position
    try:
        bits = min(reader.remaining, limits.max_bytes * 8)
        raw = reader.read_payload(bits)
        reader.position = start
        staged = BitReader(raw, bit_count=bits)
        if staged.read_bool():
            raise UnsupportedEvenComponentExport('true_export_discriminator_unsupported')
        count = int.from_bytes(staged.read_bytes(4), 'little', signed=True)
        _bound_count(count, profile, limits)
        bindings = {b.guid: b for b in profile.components}
        seen, rows = set(), []
        for _ in range(count):
            guid = staged.read_packed_int()
            binding = bindings.get(guid)
            if binding is None or guid in seen or staged.read_bits(8) != 3:
                raise UnsupportedEvenComponentExport('only_bound_even_component_flags3_supported')
            outer_guid = staged.read_packed_int()
            if outer_guid != profile.current_pawn_guid or staged.read_bits(8) != 0:
                raise UnsupportedEvenComponentExport('only_exact_existing_pawn_flags0_outer_supported')
            header = staged.read_bytes(4)
            units = int.from_bytes(header, 'little', signed=True)
            if units == -(1 << 31) or abs(units) > limits.max_path_units:
                raise ValueError('even_export_fstring_unit_bound')
            text = staged.read_bytes(abs(units) * (2 if units < 0 else 1))
            name, _ = decode_string(header + text, max_units=limits.max_path_units)
            if name != binding.name:
                raise UnsupportedEvenComponentExport('received_name_differs_from_current_profile')
            seen.add(guid)
            rows.append(EvenComponentExportNode(guid, name, ExistingPawnOuterReference(outer_guid)))
        _recheck(profile, facts)
    except Exception:
        reader.position = start
        raise
    reader.position = start + staged.position
    return tuple(rows)
