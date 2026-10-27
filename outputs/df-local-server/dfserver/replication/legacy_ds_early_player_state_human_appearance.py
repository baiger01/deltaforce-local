"""Explicit one-trial initial PS delivery dependency; no native execution claims."""
from dataclasses import dataclass, field

from dfserver.replication.legacy_ds_late_player_state_human_appearance import LatePlayerStateHumanAppearanceDiagnostic, TRIAL_OPERATOR


def namespace(items):
    return tuple((channel, item.actor_guid, item.bunch) for channel, item in sorted(items.items()))


@dataclass(frozen=True)
class EarlyPlayerStateHumanAppearanceGate:
    channel: int
    actor_guid: int
    profile: object = field(repr=False)
    owner_check: object = field(repr=False, compare=False)
    actors: tuple = field(repr=False)
    contents: tuple = field(repr=False)

    def check(self, state, peer):
        ticket = state.ticket
        if (ticket is None or type(ticket.map_id) is not int or ticket.map_id != 2201 or
                type(ticket.selected_hero_id) is not int or ticket.selected_hero_id != TRIAL_OPERATOR or
                state.client_closed or not state.client_join_observed or
                type(self.profile) is not LatePlayerStateHumanAppearanceDiagnostic or
                not callable(self.owner_check) or self.owner_check(state, peer) is not True or
                not self.profile.sources_current() or namespace(state.actor_opens) != self.actors or
                namespace(state.actor_contents) != self.contents or
                state.late_player_state_human_appearance is not None or
                state.late_player_state_human_appearance_profile is not None):
            raise ValueError('Early PlayerState trial owner, sources or namespace changed')
        opened, content = state.actor_opens.get(self.channel), state.actor_contents.get(self.channel)
        if (opened is None or content is None or opened.actor_guid != self.actor_guid or
                content.actor_guid != self.actor_guid or opened.bunch.reliable is not True or
                content.bunch.channel_sequence != (opened.bunch.channel_sequence + 1) & 1023):
            raise ValueError('Early PlayerState trial differs from its own reliable channel')
        return True
