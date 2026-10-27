"""Typed internal profiles for qualified box projections and move-result replies."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class WorldBoxReceiver:
    object_path: str
    channel_index: int
    actor_guid: int


@dataclass(frozen=True)
class WorldBoxProjection:
    object_path: str
    authority_revision: int
    stages: tuple
    cursor_after_ack: object = field(repr=False)


@dataclass(frozen=True)
class WorldDeliveryProfile:
    recipient_scope: tuple
    receivers: tuple
    project_box: object = field(repr=False)
    success_update: object = field(repr=False)
    sources_current: object = field(repr=False)
    live_world_current: object = field(repr=False)

    def __post_init__(self):
        if (type(self.recipient_scope) is not tuple or len(self.recipient_scope) != 2 or
                type(self.recipient_scope[0]) is not str or not 1 <= len(self.recipient_scope[0]) <= 256 or
                type(self.recipient_scope[1]) is not int or not 0 < self.recipient_scope[1] < 1 << 64 or
                type(self.receivers) is not tuple or not 1 <= len(self.receivers) <= 3 or
                any(type(receiver) is not WorldBoxReceiver for receiver in self.receivers) or
                any(not callable(value) for value in
                    (self.project_box, self.success_update, self.sources_current, self.live_world_current))):
            raise ValueError('A source-qualified finite world recipient profile is required')
        if (len({row.object_path for row in self.receivers}) != len(self.receivers) or
                len({row.channel_index for row in self.receivers}) != len(self.receivers) or
                len({row.actor_guid for row in self.receivers}) != len(self.receivers)):
            raise ValueError('World box receivers require distinct actual paths, channels and GUIDs')
        for row in self.receivers:
            if (type(row.object_path) is not str or not row.object_path.startswith('/Game/') or
                    type(row.channel_index) is not int or not 2 <= row.channel_index <= 65535 or
                    type(row.actor_guid) is not int or not 3 <= row.actor_guid < 1 << 32 or not row.actor_guid & 1):
                raise ValueError('An exact current static box Actor receiver is required')
