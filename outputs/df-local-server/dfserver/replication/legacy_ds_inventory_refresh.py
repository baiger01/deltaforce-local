"""Owner-supplied, source-qualified inventory refresh callbacks and stage bindings."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class InventoryRefreshProfile:
    pc_channel: int
    pc_guid: int
    pawn_channel: int
    pawn_guid: int
    component_guid: int
    initial_array_key: int
    initial_payloads: tuple
    original_items: tuple = field(repr=False)
    accept_ready: object = field(repr=False)
    project_refresh: object = field(repr=False)
    sources_current: object = field(repr=False)
    apply_update: object = field(repr=False)
    function_index: int = 225
    exclusive_index_maximum: int = 245

    def __post_init__(self):
        if (any(type(value) is not int or not 2 <= value <= 1023
                for value in (self.pc_channel, self.pawn_channel)) or
                self.pc_channel == self.pawn_channel or
                any(type(value) is not int or not 2 <= value <= 0xffffffff or value & 1
                    for value in (self.pc_guid, self.pawn_guid, self.component_guid)) or
                len({self.pc_guid, self.pawn_guid, self.component_guid}) != 3 or
                type(self.initial_array_key) is not int or not 1 <= self.initial_array_key < (1 << 31)-1 or
                self.function_index != 225 or self.exclusive_index_maximum != 245 or
                type(self.initial_payloads) is not tuple or not 2 <= len(self.initial_payloads) <= 64 or
                type(self.original_items) is not tuple or not 1 <= len(self.original_items) <= 256 or
                any(not callable(callback) for callback in
                    (self.accept_ready, self.project_refresh, self.sources_current, self.apply_update))):
            raise ValueError('An explicit source-qualified carried inventory refresh profile is required')
        ordinals = []
        for ordinal, payload, bits in self.initial_payloads:
            if (type(ordinal) is not int or not 1 <= ordinal <= 64 or type(payload) is not bytes or
                    type(bits) is not int or not 1 <= bits <= 8192 or
                    len(payload) != (bits+7)//8 or int.from_bytes(payload, 'little') >> bits):
                raise ValueError('Exact bounded original inventory continuation payloads are required')
            ordinals.append(ordinal)
        if len(set(ordinals)) != len(ordinals):
            raise ValueError('Initial inventory stages must be distinct')
