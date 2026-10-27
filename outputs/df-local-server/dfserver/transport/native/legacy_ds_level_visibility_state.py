"""Immutable latest PC-reported visibility, not native World or readiness state.

The owner supplies the qualified PC/profile/field boundary. Only the existing
string-name codec subset is admitted; no archive-name version or PackageMap
override is inferred. Caller-owned packet receipt and commit remain separate.
"""
from dataclasses import dataclass

from dfserver.replication.legacy_ds_actor_fields import ClassFieldEnvelope
from dfserver.transport.native.legacy_ds_level_visibility import MAX_BODY_BYTES, MAX_ENTRIES, MAX_NAME_UNITS, LevelVisibilityProfile, LevelVisibility, NativeName, decode_level_visibility_parameters


def _name(name):
    if (type(name) is not NativeName or type(name.text) is not str or
            name.hardcoded_index is not None or type(name.number) is not int or
            not 0 <= name.number <= 0xffffffff or '\0' in name.text or '\uffff' in name.text):
        raise ValueError('An exact decoded string-branch NativeName is required')
    try:
        units = len(name.text.encode('utf-16le'))//2 + 1
    except UnicodeError as error:
        raise ValueError('The reported NativeName text is invalid') from error
    if units > MAX_NAME_UNITS:
        raise ValueError('The reported NativeName exceeds the codec bound')


@dataclass(frozen=True)
class LevelVisibilityState:
    source_sha256: str | None = None
    records: tuple = ()
    revision: int = 0

    def __post_init__(self):
        if (type(self.records) is not tuple or len(self.records) > MAX_ENTRIES or
                type(self.revision) is not int or self.revision < 0):
            raise ValueError('A bounded immutable reported-visibility state is required')
        if self.source_sha256 is None:
            if self.records or self.revision:
                raise ValueError('Only an empty reported state can lack its profile source identity')
        elif (type(self.source_sha256) is not str or len(self.source_sha256) != 64 or
                any(c not in '0123456789abcdef' for c in self.source_sha256)):
            raise ValueError('The reported state requires its exact profile source identity')
        packages = set()
        for row in self.records:
            if (type(row) is not LevelVisibility or type(row.is_visible) is not bool or
                    type(row.file_name_omitted) is not bool):
                raise ValueError('Exact decoded visibility records are required')
            _name(row.package_name)
            _name(row.file_name)
            if (row.package_name in packages or
                    row.file_name_omitted and row.file_name != row.package_name):
                raise ValueError('Reported package keys must be unique and preserve filename omission')
            packages.add(row.package_name)


def apply(state, field, profile):
    """Decode one 83/84 field and atomically return its latest reported values.

    Full NativeName values are keys, including number; invisible reports remain
    records. A net duplicate returns the original object. Cumulative overflow
    rejects the request, without eviction or changes to the caller's state.
    """
    if (type(state) is not LevelVisibilityState or type(field) is not ClassFieldEnvelope or
            type(profile) is not LevelVisibilityProfile):
        raise ValueError('The exact immutable visibility state, field and profile are required')
    state.__post_init__()
    profile.__post_init__()
    if state.source_sha256 not in (None, profile.source_sha256):
        raise ValueError('A reported visibility state cannot change its profile source identity')
    if (type(field.payload) is not bytes or type(field.payload_bit_count) is not int or
            not 1 <= field.payload_bit_count <= MAX_BODY_BYTES*8 or
            len(field.payload) != (field.payload_bit_count+7)//8 or
            int.from_bytes(field.payload, 'little') >> field.payload_bit_count):
        raise ValueError('The visibility parameter must preserve its exact field bit boundary')
    decoded = decode_level_visibility_parameters(field.payload, field.payload_bit_count,
        rep_index=field.rep_index, profile=profile, name_version=None)
    records = {row.package_name: row for row in state.records}
    for row in decoded.levels:
        records[row.package_name] = row
        if len(records) > MAX_ENTRIES:
            raise ValueError('The cumulative reported visibility package bound was exceeded')
    latest = tuple(records.values())
    if latest == state.records and state.source_sha256 == profile.source_sha256:
        return state
    return LevelVisibilityState(profile.source_sha256, latest, state.revision+(latest != state.records))
