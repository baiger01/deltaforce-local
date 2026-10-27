"""Bounded loopback transport probe for the game's separate DS connection.

This is deliberately not a game server.  It records the first client packets
after a local match handoff so that a server implementation can be based on
observed traffic rather than an assumed Unreal transport. Explicitly enabling
handshake_probe adds a bounded plaintext challenge/ACK experiment. Native
acceptance, transport framing and gameplay still require separate verification.
"""

from collections import Counter, deque
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import threading
import time

from dfserver.transport.native.legacy_ds_handshake_probe import LegacyDSHandshakeProbe
from dfserver.transport.native.legacy_ds_control_connection import LegacyDSControlConnection, preflight_actor_content_plans, _ActualActorReceipt, ADMITTED_RECEIPT_REJECTION_CODES
from dfserver.match.legacy_ds_match_admission import LocalMatchAdmissions, LocalMatchTicket


ADMITTED_CAPTURE_SLOTS = 128
ADMITTED_CAPTURE_PHASE_SECONDS = 15
_ADMITTED_CAPTURE_EVENTS = frozenset(('admitted_actor_reliable_packet_received',
    'admitted_actor_reliable_packet_rejected', 'control_ack_only_consumed',
    'control_client_close_consumed', 'control_client_close_retry_consumed',
    'control_close_rejected', 'application_header_rejected', 'application_shape_rejected',
    'application_sequence_rejected', 'application_after_client_close',
    'qualified_receipt_forward_gap_consumed'))
_ADMISSION_SOURCE_PROFILE_FIELDS = ('inventory_refresh_profile', 'owner_switch_profile', 'movement_profile',
                                  'static_box_runtime_profile')


def _require_pc_profile_build(manifest, profile):
    """Keep current source recipes and historical Actor namespaces separate."""
    rpc_qualification = getattr(profile, 'current_qualification', None)
    actor_qualification = manifest.current_qualification
    if rpc_qualification is None:
        from dfserver.replication.legacy_ds_scalar_serializers import SHIPPING_SHA256
        if actor_qualification is not None or manifest.client_sha256 != SHIPPING_SHA256:
            raise ValueError('Historical PC RPCs require their historical Actor build')
        return
    from dfserver.replication.legacy_ds_current_actor_profile import (
        require_current_actor_manifest, current_actor_binding)
    from dfserver.transport.native.legacy_ds_current_pc_rpc_profile import require_current_profile
    require_current_profile(rpc_qualification, class_path=profile.class_path,
        exclusive_index_maximum=profile.exclusive_index_maximum, source_sha256=profile.source_sha256)
    if (require_current_actor_manifest(manifest) != 'PlayerController' or
            current_actor_binding(actor_qualification, 'PlayerController')['exclusive_cache_index_maximum'] !=
            profile.exclusive_index_maximum or
            any(dict(actor_qualification.source_pins).get(path) != digest
                for path, digest in rpc_qualification.source_pins)):
        raise ValueError('Current PC Actor and RPC sources must agree')


@dataclass(frozen=True, repr=False)
class _PCRestartObserverOwner:
    probe: object
    connection: object
    registration: object
    ticket: object
    generation: object
    transport: object
    peer: tuple
    profile: tuple
    actor_fields: tuple
    actor_namespace: tuple
    content_namespace: tuple


class GameServerProbe:
    def __init__(self, capture_dir, *, port=0, max_packets=16, max_bytes=65535,
                 handshake_probe=False, packet_ack_probe=False,
                 control_probe=False, expected_net_version=None, control_max_packet_bytes=1024,
                 control_welcome_maps=None, require_initial_actor_profile=False):
        if type(require_initial_actor_profile) is not bool:
            raise ValueError('Initial Actor profile requirement must be an explicit boolean')
        if control_probe and not packet_ack_probe:
            raise ValueError('Native control step requires the packet transport probe')
        if packet_ack_probe and not handshake_probe:
            raise ValueError('Packet ACK probe requires the bounded handshake')
        if (type(port) is not int or not 0 <= port <= 65535 or
                type(max_packets) is not int or max_packets < 1 or
                type(max_bytes) is not int or not 1 <= max_bytes <= 65535):
            raise ValueError('Invalid bounded game-server probe configuration')
        self.capture_dir = Path(capture_dir)
        self.max_packets = max_packets
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._fashion_async_bridge = None
        self._report_lock = threading.Lock()
        self._persistence_condition = threading.Condition()
        self._persistence_queue = deque()
        self._persistence_thread = None
        self._persistence_stop = False
        self._persistence_busy = False
        self._report_requested = self._report_completed = 0
        self._persistence_state = 'stopped'
        self._persistence_errors = Counter()
        self._persistence_failure = None
        self._persistence_has_failure = False
        self._io_context = threading.local()
        self._source_cycle_processing = {phase: {'count': 0, 'total_seconds': 0.0, 'max_seconds': 0.0}
                                         for phase in ('receive', 'timer')}
        self._stop = threading.Event()
        self._records = []
        self._tcp_accepted = 0
        self._tcp_accept_samples = []
        self._threads = []
        self._udp_receive_thread = None
        self._udp_receive_state = 'stopped'
        self._udp_receive_errors = Counter()
        self._udp_receive_failure = None
        if control_welcome_maps is not None and not control_probe:
            raise ValueError('Welcome maps require the native control exchange')
        self._admissions = LocalMatchAdmissions() if control_welcome_maps is not None else None
        if require_initial_actor_profile and self._admissions is None:
            raise ValueError('Required initial Actor profiles need native map admissions')
        self._require_initial_actor_profile = require_initial_actor_profile
        self._welcome_map_ids = frozenset(control_welcome_maps or {})
        self._handshake = LegacyDSHandshakeProbe(packet_ack_probe=packet_ack_probe,
            control_probe=control_probe, expected_net_version=expected_net_version,
            control_max_packet_bytes=control_max_packet_bytes,
            control_admissions=self._admissions, control_welcome_maps=control_welcome_maps,
            verified_session_ttl=3600 if control_welcome_maps is not None else 120,
            transport_keepalive=bool(require_initial_actor_profile and control_probe and
                                     self._admissions is not None and control_welcome_maps is not None),
            qualified_receipt_forward_gaps=bool(require_initial_actor_profile and control_probe and
                                     self._admissions is not None and control_welcome_maps is not None),
            max_verified_session_ttl=3600 if control_welcome_maps is not None else 600) if handshake_probe else None
        if (require_initial_actor_profile and self._admissions is not None and
                control_welcome_maps is not None and self._handshake is not None and
                isinstance(self._handshake.packet_ack_probe, LegacyDSControlConnection)):
            self._handshake.packet_ack_probe.configure_local_stage_retries(self._local_stage_generation)
        # Windows monotonic() can repeat for 15.625 ms; elapsed movement time
        # uses the same high-resolution monotonic counter at every boundary.
        self._started_at = time.perf_counter()
        self._handshake_sent = 0
        self._packet_ack_sent = 0
        self._control_sent = 0
        self._transport_keepalive_sent = 0
        self._actor_open_sent = 0
        self._actor_content_sent = 0
        self._player_state_human_appearance_sent = 0
        self._early_player_state_human_appearance_sent = 0
        self._early_player_state_human_appearance_profiles = {}
        self._pc_restart_sent = 0
        self._pc_restart_capture = None
        self._pc_restart_records = []
        self._pc_restart_capture_skips = Counter()
        self._admitted_receipt_capture = None
        self._admitted_receipt_capture_epoch = 0
        self._registered_bootstraps = {}
        self._initial_actor_profiles = {}
        self._local_map_rule_profiles = {}
        self._prepared_local_rooms = {}
        self._pc_ping_profiles = {}
        self._pc_startup_profiles = {}
        self._pc_restart_profiles = {}
        self._pc_restart_manifests = {}
        self._pc_view_target_profiles = {}
        self._pc_view_target_sent = 0
        self._pc_rotation_profiles = {}
        self._pc_rotation_sent = 0
        self._pc_hud_profiles = {}
        self._pc_hud_sent = 0
        self._game_state_start_profiles = {}
        self._bootstrap_events = Counter()
        self._source_cleanup_errors = Counter()
        self._source_cleanup_pending = {}
        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._tcp.bind(('127.0.0.1', port))
            self._udp.bind(self._tcp.getsockname())
            self._tcp.listen(4)
            self._tcp.settimeout(.2)
            self._udp.settimeout(.2)
        except BaseException:
            self._tcp.close()
            self._udp.close()
            raise
        self.port = self._tcp.getsockname()[1]

    def _local_stage_generation(self, peer, state, transport):
        """Only the current joined ticket and verified peer generation may retry."""
        handshake = self._handshake
        connection = handshake.packet_ack_probe
        generation = handshake.pending.get(peer)
        if (generation is None or not generation.echoed or generation.verified_at is None or
                connection.control_peers.get(peer) is not state or connection.peers.get(peer) is not transport or
                handshake.current_peer_for_generation(generation, state.ticket) != peer):
            return None
        return generation

    @property
    def records(self):
        with self._lock:
            return [record.copy() for record in self._records]

    @property
    def map_join_progress(self):
        """Observe active local Join9 admissions without exposing ticket values."""
        with self._lock:
            if self._handshake is not None:
                self._handshake._expire(time.perf_counter() - self._started_at)
            connection = self._handshake.packet_ack_probe if self._handshake else None
            joined, active = 0, 0
            if isinstance(connection, LegacyDSControlConnection) and self._admissions is not None:
                joined = connection.joined_count
                for peer, state in connection.control_peers.items():
                    ticket = state.ticket
                    generation = self._handshake.pending.get(peer)
                    if (state.client_join_observed and not state.client_closed and
                            ticket is not None and self._admissions.is_active(ticket) and
                            connection.ticket_peers.get(ticket.cookie) == peer and
                            peer in connection.peers and generation is not None and
                            generation.verified_at is not None):
                        active += 1
            return {'join_observed_count': joined, 'active_joined_peers': active,
                    'playable_map_verified': False}

    @property
    def actor_transport_progress(self):
        return self.actor_transport_delivery_progress()

    def actor_transport_delivery_progress(self, *, require_post_open_contents=False):
        """Current whole-ticket delivery sets; transport ACKs never prove a spawn."""
        if type(require_post_open_contents) is not bool:
            raise ValueError('Post-open delivery requirement must be an explicit boolean')
        with self._lock:
            return self._actor_transport_delivery_progress_locked(
                require_post_open_contents=require_post_open_contents)

    def _actor_transport_delivery_progress_locked(self, *, require_post_open_contents=False):
        """Inspect delivery and its admission while the caller holds _lock."""
        if self._handshake is not None:
            self._handshake._expire(time.perf_counter() - self._started_at)
        connection = self._handshake.packet_ack_probe if self._handshake else None
        acknowledgments = (connection.summary()['initial_actor_delivery_acks']
            if isinstance(connection, LegacyDSControlConnection) else 0)
        fully_delivered_sets = 0
        if isinstance(connection, LegacyDSControlConnection) and self._admissions is not None:
            self._expire_registered_bootstraps_locked()
            for cookie, registration in self._registered_bootstraps.items():
                if registration['status'] != 'queued':
                    continue
                ticket = registration['ticket']
                peer, generation = registration['peer'], registration['generation']
                state = connection.control_peers.get(peer)
                if (not self._admissions.is_active(ticket) or
                        connection.ticket_peers.get(cookie) != peer or
                        generation is None or generation.verified_at is None or
                        self._handshake.pending.get(peer) is not generation or
                        peer not in connection.peers or state is None or
                        state.ticket is not ticket or not state.client_join_observed or
                        state.client_closed):
                    continue
                # Never combine deliveries from different owners or generations.
                fields = registration['actor_fields']
                opens_delivered = fields and all(
                        (delivery := state.actor_opens.get(item['channel_index'])) is not None and
                        delivery.actor_guid == item['actor_guid'] and delivery.delivered
                        for item in fields)
                if not opens_delivered:
                    continue
                if require_post_open_contents:
                    plans = registration.get('post_open_actor_contents')
                    if (type(plans) is not tuple or not plans or
                            set(state.actor_opens) != {item['channel_index'] for item in fields}):
                        continue
                    try:
                        sources = self._owned_admission_sources(
                            registration.get(name) for name in _ADMISSION_SOURCE_PROFILE_FIELDS)
                        if not all(source() for source in sources.values()):
                            continue
                        inputs = (fields, plans, state.initial_actor_sequence, connection.max_packet_bytes)
                        cached = registration.get('content_delivery_preflight')
                        if cached is None or cached[0] != inputs:
                            expected = preflight_actor_content_plans(fields, plans,
                                initial_channel_sequence=state.initial_actor_sequence,
                                max_packet_bytes=connection.max_packet_bytes)
                            # Keep a detached input snapshot so in-place edits also invalidate it.
                            registration['content_delivery_preflight'] = (deepcopy(inputs), expected)
                        else:
                            expected = cached[1]
                    except (ValueError, TypeError, KeyError):
                        registration.pop('content_delivery_preflight', None)
                        continue
                    if (set(state.actor_contents) != set(expected) or not all(
                            (delivery := state.actor_contents.get(channel)) is not None and
                            delivery.actor_guid == expected_delivery.actor_guid and
                            delivery.bunch == expected_delivery.bunch and
                            delivery.content_dependencies == expected_delivery.content_dependencies and
                            delivery.content_stage_dependencies == expected_delivery.content_stage_dependencies and
                            delivery.content_stage_policy == expected_delivery.content_stage_policy and delivery.delivered and
                            len(delivery.continuations) == len(expected_delivery.continuations) and all(
                                actual.actor_guid == wanted.actor_guid and actual.bunch == wanted.bunch and
                                actual.content_dependencies == wanted.content_dependencies and
                                actual.content_stage_dependencies == wanted.content_stage_dependencies and
                                actual.content_stage_policy == wanted.content_stage_policy and actual.delivered
                                for actual, wanted in zip(delivery.continuations, expected_delivery.continuations))
                            for channel, expected_delivery in expected.items())):
                        continue
                fully_delivered_sets += 1
        return {'datagrams_sent': self._actor_open_sent,
                'delivery_acks': acknowledgments,
                'fully_delivered_sets': fully_delivered_sets,
                'native_spawn_verified': False}

    def single_delivered_loadout_snapshot(self):
        """Read one exact admission for a private, post-delivery diagnostic.

        A later lobby/database read is not the loadout sent to this client.
        This does not verify native receipt, OnRep execution or a playable map.
        """
        with self._lock:
            progress = self._actor_transport_delivery_progress_locked(require_post_open_contents=True)
            registrations = [r for r in self._registered_bootstraps.values()
                if r['status'] == 'queued' and self._admissions is not None and
                self._admissions.is_active(r['ticket'])]
            if progress['fully_delivered_sets'] != 1 or len(registrations) != 1:
                raise ValueError('One complete current admission content set is required for observation')
            raw = registrations[0]['ticket'].loadout_snapshot
            if type(raw) is not bytes or not 0 < len(raw) <= 1024*1024:
                raise ValueError('The complete admission has no bounded immutable loadout snapshot')
            return raw

    @property
    def listening(self):
        return (self._udp_receive_thread is not None and self._udp_receive_thread.is_alive()
                and self._udp_receive_state in ('starting', 'running') and not self._stop.is_set())

    @property
    def match_admission_enabled(self):
        return self._admissions is not None

    @property
    def initial_actor_profile_required(self):
        return self._require_initial_actor_profile

    def match_admission_ready(self, map_id):
        """Only a published, preflighted profile satisfies the opt-in gate."""
        with self._lock:
            return (type(map_id) is int and self._admissions is not None and
                    self.listening and map_id in self._welcome_map_ids and
                    (not self._require_initial_actor_profile or
                     map_id in self._initial_actor_profiles))

    def match_appearance_required(self, map_id):
        with self._lock:
            profile = self._initial_actor_profiles.get(map_id)
            return bool(profile and profile.get('admission_content_factory') is not None)

    def set_local_map_rules(self, map_id, sources_raw, items_raw, config_raw, *, match_mode_ids):
        """Install validated owner-side rules for future single-human rooms."""
        from dfserver.match.legacy_ds_local_map_rules import simulate_local_map_rules
        if (type(match_mode_ids) is not frozenset or not match_mode_ids or
                any(type(v) is not int or not 0 < v < 1 << 32 for v in match_mode_ids)):
            raise ValueError('Explicit source-qualified match modes are required')
        sample = simulate_local_map_rules(sources_raw, items_raw, config_raw, seed=0)
        if type(map_id) is not int or map_id != sample['map_id']:
            raise ValueError('Local rules must match their source-qualified map ID')
        with self._lock:
            profile = self._initial_actor_profiles.get(map_id)
            if (not profile or profile.get('room_capacity') != 1 or self._registered_bootstraps or
                    map_id in self._local_map_rule_profiles):
                raise ValueError('Local map rules require an unused qualified single-human profile')
            self._local_map_rule_profiles[map_id] = (sources_raw, items_raw, config_raw, match_mode_ids)

    def _prepare_match_room_locked(self, player_id, room_id, map_id, match_mode_id):
        from dfserver.match.legacy_ds_local_map_rules import simulate_local_map_rules
        for value, bits in ((player_id, 64), (room_id, 64), (map_id, 32), (match_mode_id, 32)):
            if type(value) is not int or not 0 < value < 1 << bits:
                raise ValueError('Bounded actual local room identities are required')
        profile = self._local_map_rule_profiles.get(map_id)
        if profile is None or match_mode_id not in profile[3] or not self.listening:
            raise ValueError('No qualified local rules for the selected mode')
        now = time.perf_counter()
        for key, room in list(self._prepared_local_rooms.items()):
            if ((room['ticket'] is None and now >= room['prepared_until']) or
                    (room['ticket'] is not None and not self._admissions.is_active(room['ticket']))):
                del self._prepared_local_rooms[key]
        key = (player_id, room_id, map_id, match_mode_id)
        if key not in self._prepared_local_rooms:
            if len(self._prepared_local_rooms) >= 16:
                raise ValueError('The bounded local room preparation capacity is full')
            world = simulate_local_map_rules(*profile[:3], seed=secrets.randbits(63))
            self._prepared_local_rooms[key] = dict(world_state=world, ticket=None, prepared_until=now + 3600)
        return self._prepared_local_rooms[key]

    def prepare_match_room(self, *, player_id, room_id, map_id, match_mode_id):
        """Freeze one owner-side rule result before the native Prepare notice."""
        with self._lock:
            if map_id not in self._local_map_rule_profiles:
                return None
            return deepcopy(self._prepare_match_room_locked(player_id, room_id, map_id, match_mode_id)['world_state'])

    def match_room_world_state(self, ticket):
        """Read this exact active admission's frozen state without credentials."""
        with self._lock:
            if type(ticket) is not LocalMatchTicket or self._admissions is None:
                raise ValueError('An exact current local rule admission is required')
            registration = self._registered_bootstraps.get(ticket.cookie)
            if (not self._admissions.is_active(ticket) or registration is None or
                    registration['ticket'] is not ticket or 'local_world_state' not in registration):
                raise ValueError('The local rule admission is no longer active')
            return deepcopy(registration['local_world_state'])

    def cancel_match_admission(self, ticket):
        """Cancel only an exact locally issued allocation, including its lease."""
        with self._lock:
            return self._cancel_match_admission_locked(ticket)

    def _cancel_match_admission_locked(self, ticket):
        if self._admissions is None or not self._admissions.is_active(ticket):
            return False
        registration = self._registered_bootstraps.get(ticket.cookie)
        if registration is not None and registration['ticket'] is not ticket:
            return False
        self._admissions.revoke(ticket)
        if registration is not None:
            registration['status'] = 'cancelled'
        self._release_admission_sources_locked(ticket)
        for key, room in list(self._prepared_local_rooms.items()):
            if room['ticket'] is ticket:
                del self._prepared_local_rooms[key]
        self._bootstrap_events['allocation_cancelled'] += 1
        return True

    @staticmethod
    def _owned_admission_sources(profiles):
        sources = {}
        for profile in profiles:
            source = getattr(profile, 'sources_current', None)
            if (getattr(type(source), '_probe_owned_source_lease', False) is True and
                    callable(getattr(source, 'close', None))):
                sources[id(source)] = source
        return sources

    def _release_admission_sources_locked(self, ticket=None, profiles=(), *, closing=False):
        """Release opted-in leases, preserving any other current admission's use."""
        selected, protected = list(profiles), []
        for registration in self._registered_bootstraps.values():
            current = registration['ticket']
            values = tuple(registration.get(name) for name in _ADMISSION_SOURCE_PROFILE_FIELDS)
            if closing or current is ticket:
                selected.extend(values)
                registration['static_box_runtime'] = None
            elif (registration['status'] in ('waiting_for_join', 'queued') and
                    self._admissions is not None and self._admissions.is_active(current)):
                protected.extend(values)
        connection = self._handshake.packet_ack_probe if self._handshake else None
        if isinstance(connection, LegacyDSControlConnection):
            for state in connection.control_peers.values():
                current = state.ticket
                values = tuple(getattr(state, name, None) for name in _ADMISSION_SOURCE_PROFILE_FIELDS)
                if closing or current is ticket:
                    selected.extend(values)
                elif (current is not None and not state.client_closed and
                        self._admissions is not None and self._admissions.is_active(current)):
                    registration = self._registered_bootstraps.get(current.cookie)
                    if (registration is None or registration['ticket'] is current and
                            registration['status'] in ('waiting_for_join', 'queued')):
                        protected.extend(values)
        held = self._owned_admission_sources(protected)
        sources = self._owned_admission_sources(selected)
        sources.update(self._source_cleanup_pending)
        for identity, source in sources.items():
            if identity not in held:
                try:
                    source.close()
                except Exception as error:
                    error_type = ('OSError' if isinstance(error, OSError) else
                                  'ValueError' if isinstance(error, ValueError) else 'Exception')
                    self._source_cleanup_errors[error_type] += 1
                    self._source_cleanup_pending[identity] = source
                else:
                    self._source_cleanup_pending.pop(identity, None)

    def cancel_unjoined_match_allocations(self, player_id):
        """A new authenticated lobby allocation may replace its unjoined tickets."""
        if type(player_id) is not int or not 0 < player_id < 1 << 64:
            raise ValueError('An actual authenticated local player is required')
        with self._lock:
            if self._admissions is None:
                return 0
            tickets = [r['ticket'] for r in self._registered_bootstraps.values()
                       if r['ticket'].player_id == player_id and
                       not self._admissions.has_joined_session(r['ticket'])]
            return sum(self._cancel_match_admission_locked(ticket) for ticket in tickets)

    def cancel_player_solo_match_allocations(self, player_id):
        """An authenticated new solo StartAlloc replaces this owner's old rooms.

        A lobby reconnect has no TCP-local handoff, although the previous Join
        lease can still occupy its single-player room. Do not retire somebody
        else's allocation or a room this player joined as another owner's guest.
        """
        if type(player_id) is not int or not 0 < player_id < 1 << 64:
            raise ValueError('An actual authenticated local player is required')
        with self._lock:
            if self._admissions is None:
                return 0
            tickets = self._admissions.active_player_solo_tickets(player_id)
            count = sum(self._cancel_match_admission_locked(ticket) for ticket in tickets)
            for key, room in list(self._prepared_local_rooms.items()):
                if key[:2] == (player_id, player_id) and room['ticket'] is None:
                    del self._prepared_local_rooms[key]
            return count

    def cancel_prepared_match(self, *, player_id, room_id, map_id, match_mode_id):
        """Release only an unissued owner-side preparation, never another ticket."""
        with self._lock:
            key = (player_id, room_id, map_id, match_mode_id)
            room = self._prepared_local_rooms.get(key)
            if room is None or room['ticket'] is not None:
                return False
            del self._prepared_local_rooms[key]
            return True

    def issue_match_admission(self, *, player_id, room_id, map_id, match_mode_id,
                              selected_hero_id=None, selected_fashion_id=None, loadout_snapshot=None):
        from contextlib import nullcontext
        with self._lock:
            profile = self._initial_actor_profiles.get(map_id)
            qualify = profile.get('admission_qualification_scope') if profile else None
        ticket = None
        try:
            with qualify() if qualify is not None else nullcontext():
                ticket = self._issue_match_admission(player_id=player_id, room_id=room_id,
                    map_id=map_id, match_mode_id=match_mode_id, selected_hero_id=selected_hero_id,
                    selected_fashion_id=selected_fashion_id, loadout_snapshot=loadout_snapshot)
        except BaseException:
            if ticket is not None:
                self.cancel_match_admission(ticket)
            raise
        return ticket

    def _issue_match_admission(self, *, player_id, room_id, map_id, match_mode_id,
                               selected_hero_id=None, selected_fashion_id=None, loadout_snapshot=None):
        from dfserver.replication.legacy_ds_actor_manifest import preflight_actor_manifest
        if self._admissions is None or not self.listening or map_id not in self._welcome_map_ids:
            raise ValueError('No active evidenced map admission on this local DS')
        with self._lock:
            profile = self._initial_actor_profiles.get(map_id)
            if self._require_initial_actor_profile and not profile:
                raise ValueError('Required initial Actor profile is not ready for this local map')
            plans = profile['post_open_actor_contents'] if profile else ()
            factory = profile.get('admission_content_factory') if profile else None
            loadout_factory = profile.get('admission_loadout_content_factory') if profile else None
            ticket_factory = profile.get('admission_ticket_content_factory') if profile else None
            actor_factory = profile.get('admission_ticket_actor_factory') if profile else None
            room_factory = profile.get('admission_room_content_factory') if profile else None
            character_factory = profile.get('admission_character_initialization_factory') if profile else None
            owned_channels_factory = profile.get('admission_owned_actor_channels_factory') if profile else None
            inventory_refresh_factory = profile.get('admission_inventory_refresh_factory') if profile else None
            owner_switch_factory = profile.get('admission_owner_switch_factory') if profile else None
            movement_factory = profile.get('admission_movement_factory') if profile else None
            static_box_factory = profile.get('admission_static_box_runtime_factory') if profile else None
            if factory is not None:
                # Resolve and validate before allocating a cookie. The returned
                # content belongs only to this admission, never the map profile.
                plans = factory(player_id, selected_hero_id, selected_fashion_id, deepcopy(plans))
            if loadout_factory is not None:
                if type(loadout_snapshot) is not bytes or not 0 < len(loadout_snapshot) <= 1024*1024:
                    raise ValueError('Native carried content requires its bounded immutable account snapshot')
                plans = loadout_factory(player_id, selected_hero_id, selected_fashion_id,
                                        loadout_snapshot, deepcopy(plans))
            if factory is not None or loadout_factory is not None:
                connection = self._handshake.packet_ack_probe
                fields = tuple(dict(preflight_actor_manifest(m, channel_sequence=1023,
                    max_packet_bytes=connection.max_packet_bytes).actor_fields) for m in profile['manifests'])
                preflight_actor_content_plans(fields, plans, initial_channel_sequence=1023,
                    max_packet_bytes=connection.max_packet_bytes)
            room = None
            if map_id in self._local_map_rule_profiles:
                room = self._prepared_local_rooms.get((player_id, room_id, map_id, match_mode_id))
                if room is None or (room['ticket'] is None and time.perf_counter() >= room['prepared_until']):
                    raise ValueError('A current native Prepare is required before local rule admission')
            if room_factory is not None and room is None:
                raise ValueError('Room content requires this admission\'s frozen native Prepare state')
            room_context = deepcopy(room['world_state']) if room_factory is not None else None
            room_policy = ({'room_capacity': profile['room_capacity']}
                           if profile and profile.get('room_capacity') is not None else {})
            if room is not None:
                room_policy['room_seed'] = room['world_state']['seed']
            ticket = self._admissions.issue(player_id, room_id, map_id, match_mode_id,
                selected_hero_id, selected_fashion_id, loadout_snapshot=loadout_snapshot, **room_policy)
            if room is not None:
                room['ticket'] = ticket
        if profile:
            inventory_refresh = owner_switch = movement = static_box_profile = None
            try:
                manifests = profile['manifests']
                if actor_factory is not None:
                    result = actor_factory(ticket, deepcopy(manifests), deepcopy(plans))
                    if (type(result) is not tuple or len(result) != 2 or
                            any(type(value) is not tuple for value in result)):
                        raise ValueError('The ticket Actor producer requires manifest and content plan tuples')
                    manifests, plans = result
                if ticket_factory is not None:
                    plans = ticket_factory(ticket, deepcopy(plans))
                if room_factory is not None:
                    plans = room_factory(ticket, room_context, deepcopy(plans))
                if character_factory is not None:
                    plans = character_factory(ticket, deepcopy(manifests), deepcopy(plans))
                    if type(plans) is not tuple:
                        raise ValueError('Character initialization requires complete immutable content plans')
                owned_channels = None
                if owned_channels_factory is not None:
                    owned_channels = owned_channels_factory(ticket, deepcopy(manifests), deepcopy(plans))
                    actual_channels = {m.channel_index for m in manifests if not m.actor_guid & 1}
                    if (type(owned_channels) is not tuple or len(owned_channels) > 14 or
                            any(type(c) is not int or c not in actual_channels for c in owned_channels) or
                            len(set(owned_channels)) != len(owned_channels)):
                        raise ValueError('Owned reliable receipt channels require distinct admitted dynamic Actors')
                inventory_refresh = (inventory_refresh_factory(ticket, deepcopy(manifests), deepcopy(plans))
                    if inventory_refresh_factory is not None else None)
                owner_switch = (owner_switch_factory(ticket, deepcopy(manifests), deepcopy(plans))
                    if owner_switch_factory is not None else None)
                movement = (movement_factory(ticket, deepcopy(manifests), deepcopy(plans))
                    if movement_factory is not None else None)
                static_box_profile = (static_box_factory(ticket, deepcopy(manifests), deepcopy(plans))
                    if static_box_factory is not None else None)
                self.register_initial_actor_manifests(ticket, manifests,
                    resolver=profile['resolver'], post_open_actor_contents=plans,
                    admitted_owned_actor_channels=owned_channels, inventory_refresh_profile=inventory_refresh,
                    owner_switch_profile=owner_switch, movement_profile=movement,
                    static_box_runtime_profile=static_box_profile,
                    level_visibility_profile=profile.get('level_visibility_profile'))
                if room is not None:
                    with self._lock:
                        registration = self._registered_bootstraps[ticket.cookie]
                        if (self._prepared_local_rooms.get((player_id, room_id, map_id, match_mode_id)) is not room
                                or room['ticket'] is not ticket or not self._admissions.is_active(ticket)):
                            raise ValueError('The frozen local room reservation was cancelled or replaced')
                        registration['local_world_state'] = deepcopy(room['world_state'])
            except Exception:
                self._admissions.revoke(ticket)
                with self._lock:
                    registration = self._registered_bootstraps.get(ticket.cookie)
                    if registration is not None and registration['ticket'] is ticket:
                        registration['status'] = 'cancelled'
                    self._release_admission_sources_locked(ticket,
                        (inventory_refresh, owner_switch, movement, static_box_profile))
                    if room is not None and room['ticket'] is ticket:
                        room['ticket'] = None
                raise
        return ticket

    def match_admission_ticket_active(self, ticket):
        """Check this exact handoff without issuing or refreshing its ticket."""
        with self._lock:
            if (self._admissions is None or self._handshake is None or not self.listening or
                    not self._admissions.is_active(ticket)):
                return False
            self._handshake._expire(time.perf_counter() - self._started_at)
            connection = self._handshake.packet_ack_probe if self._handshake else None
            if not isinstance(connection, LegacyDSControlConnection):
                return False
            registration = self._registered_bootstraps.get(ticket.cookie)
            if (self._require_initial_actor_profile and
                    (ticket.map_id not in self._initial_actor_profiles or registration is None)):
                return False
            if registration is not None and registration['ticket'] is not ticket:
                return False
            if registration is not None and registration['status'] in (
                    'rejected', 'cancelled', 'closed', 'client_closed'):
                return False
            if any(state.ticket is ticket and state.client_closed
                   for state in connection.control_peers.values()):
                return False
            peer = connection.ticket_peers.get(ticket.cookie)
            if peer is None:
                if registration is not None and registration['status'] == 'queued':
                    return False
                # An issued ticket can still be waiting for its first Login,
                # but an already bound state cannot lose its owner mapping.
                return not any(state.ticket is ticket for state in connection.control_peers.values())
            state = connection.control_peers.get(peer)
            generation = self._handshake.pending.get(peer)
            if registration is not None and registration['status'] == 'queued' and (
                    registration['peer'] != peer or registration['generation'] is not generation):
                return False
            return (peer in connection.peers and state is not None and
                    state.ticket is ticket and not state.client_closed and
                    generation is not None and generation.verified_at is not None)

    def set_initial_actor_manifests(self, map_id, manifests, *, resolver=None,
                                    post_open_actor_contents=(), early_player_state_human_appearance=None,
                                    admission_content_factory=None, room_capacity=None,
                                    admission_loadout_content_factory=None,
                                    admission_ticket_content_factory=None,
                                    admission_ticket_actor_factory=None,
                                    admission_room_content_factory=None,
                                    admission_character_initialization_factory=None,
                                    admission_owned_actor_channels_factory=None,
                                    admission_inventory_refresh_factory=None,
                                    admission_owner_switch_factory=None,
                                    admission_movement_factory=None, level_visibility_profile=None,
                                    admission_static_box_runtime_factory=None,
                                    admission_qualification_scope=None):
        """Configure observed templates for future tickets of one local map.

        This owner-side operation has no client-facing endpoint and no default
        templates. An optional internal producer resolves detached fields once
        after the ticket joins. Preflight is not native object resolution.
        A ticket Actor producer receives the frozen ticket and detached manifest
        and content tuples before the ticket content producer; its result still
        passes the complete manifest and packet preflight.
        """
        from dfserver.replication.legacy_ds_actor_manifest import preflight_actor_manifest

        if (type(map_id) is not int or map_id not in self._welcome_map_ids or
                type(manifests) is not tuple or not 1 <= len(manifests) <= 16 or
                resolver is not None and not callable(resolver) or
                admission_content_factory is not None and not callable(admission_content_factory) or
                admission_loadout_content_factory is not None and not callable(admission_loadout_content_factory) or
                admission_ticket_content_factory is not None and not callable(admission_ticket_content_factory) or
                admission_ticket_actor_factory is not None and not callable(admission_ticket_actor_factory) or
                admission_room_content_factory is not None and not callable(admission_room_content_factory) or
                admission_character_initialization_factory is not None and not callable(admission_character_initialization_factory) or
                admission_owned_actor_channels_factory is not None and not callable(admission_owned_actor_channels_factory) or
                admission_inventory_refresh_factory is not None and not callable(admission_inventory_refresh_factory) or
                admission_owner_switch_factory is not None and not callable(admission_owner_switch_factory) or
                admission_movement_factory is not None and not callable(admission_movement_factory) or
                admission_static_box_runtime_factory is not None and not callable(admission_static_box_runtime_factory) or
                admission_qualification_scope is not None and not callable(admission_qualification_scope) or
                room_capacity is not None and (type(room_capacity) is not int or not 1 <= room_capacity <= 4096)):
            raise ValueError('An evidenced local map and bounded manifest tuple are required')
        if level_visibility_profile is not None:
            from dfserver.transport.native.legacy_ds_level_visibility import LevelVisibilityProfile
            if type(level_visibility_profile) is not LevelVisibilityProfile:
                raise ValueError('One explicitly qualified owning level visibility profile is required')
            level_visibility_profile.__post_init__()
        with self._lock:
            connection = self._handshake.packet_ack_probe if self._handshake else None
            if not self.listening or not isinstance(connection, LegacyDSControlConnection):
                raise ValueError('An active native local connection is required for the Actor profile')
            staged = tuple(preflight_actor_manifest(manifest, channel_sequence=1023,
                max_packet_bytes=connection.max_packet_bytes) for manifest in manifests)
            self._validate_actor_field_set(tuple(item.actor_fields for item in staged))
            early = None
            if early_player_state_human_appearance is not None:
                if (admission_content_factory is not None or admission_loadout_content_factory is not None or
                        admission_ticket_content_factory is not None or admission_ticket_actor_factory is not None or
                        admission_room_content_factory is not None or
                        admission_character_initialization_factory is not None or
                        admission_owned_actor_channels_factory is not None):
                    raise ValueError('Fixed early appearance and per-admission appearance are exclusive')
                post_open_actor_contents, early = self._prepare_early_player_state_human_appearance(
                    map_id, manifests, post_open_actor_contents, early_player_state_human_appearance, connection)
            preflight_actor_content_plans(tuple(dict(item.actor_fields) for item in staged),
                post_open_actor_contents, initial_channel_sequence=1023,
                max_packet_bytes=connection.max_packet_bytes)
            configured = {'manifests': manifests, 'resolver': resolver,
                'post_open_actor_contents': tuple(dict(plan) for plan in post_open_actor_contents),
                'admission_content_factory': admission_content_factory, 'room_capacity': room_capacity,
                'admission_loadout_content_factory': admission_loadout_content_factory,
                'admission_ticket_content_factory': admission_ticket_content_factory,
                'admission_ticket_actor_factory': admission_ticket_actor_factory,
                'admission_room_content_factory': admission_room_content_factory,
                'admission_character_initialization_factory': admission_character_initialization_factory,
                'admission_owned_actor_channels_factory': admission_owned_actor_channels_factory,
                'admission_inventory_refresh_factory': admission_inventory_refresh_factory,
                'admission_owner_switch_factory': admission_owner_switch_factory,
                'admission_movement_factory': admission_movement_factory,
                'admission_static_box_runtime_factory': admission_static_box_runtime_factory,
                'admission_qualification_scope': admission_qualification_scope,
                'level_visibility_profile': level_visibility_profile}
            # Every admission reads under this same lock: no published profile
            # can issue a ticket between manifest and early-policy validation.
            if early is not None:
                self._early_player_state_human_appearance_profiles[map_id] = (configured, *early)
            self._initial_actor_profiles[map_id] = configured
        self._write_report()

    def queue_actor_open(self, *, player_id, room_id, **actor_fields):
        """Internal producer entry: bind an explicit Actor to one joined local ticket.

        This does not infer classes, object paths, a spawn or replicated state.
        It is not exposed as a client-facing API and is never called by default.
        """
        if any(type(value) is not int or not 0 < value <= (1 << 64) - 1
               for value in (player_id, room_id)):
            raise ValueError('An explicit local player and room binding is required')
        with self._lock:
            if not self.listening or self._handshake is None:
                raise ValueError('No active local Actor transport')
            self._handshake._expire(time.perf_counter() - self._started_at)
            connection = self._handshake.packet_ack_probe
            if not isinstance(connection, LegacyDSControlConnection):
                raise ValueError('Actor transport requires the local ticket connection')
            peers = [peer for peer, state in connection.control_peers.items()
                     if state.client_join_observed and not state.client_closed and state.ticket is not None and
                     state.ticket.player_id == player_id and state.ticket.room_id == room_id]
            if len(peers) != 1:
                raise ValueError('No unique joined peer for the local player and room')
            connection.queue_actor_open(peers[0], **actor_fields)

    def register_initial_actor_manifests(self, ticket, manifests, *, resolver=None,
                                       post_open_actor_contents=(), admitted_owned_actor_channels=None,
                                       inventory_refresh_profile=None, owner_switch_profile=None,
                                       movement_profile=None, level_visibility_profile=None,
                                       static_box_runtime_profile=None):
        """Register explicit templates for this exact local ticket before Join.

        The owner-side producer supplies observed object paths; this entry never
        guesses them or accepts a client-supplied Actor/property payload. A set is
        sent only after the matching admission has joined the local connection.
        """
        from dfserver.replication.legacy_ds_actor_manifest import preflight_actor_manifest

        if (type(manifests) is not tuple or not 1 <= len(manifests) <= 16 or
                resolver is not None and not callable(resolver)):
            raise ValueError('A bounded immutable initial Actor manifest set is required')
        with self._lock:
            if (not self.listening or self._handshake is None or self._admissions is None or
                    not self._admissions.is_active(ticket)):
                raise ValueError('Bootstrap registration requires an active issued local ticket')
            connection = self._handshake.packet_ack_probe
            if not isinstance(connection, LegacyDSControlConnection):
                raise ValueError('Bootstrap registration requires the admitted native connection')
            self._expire_registered_bootstraps_locked()
            if ticket.cookie in self._registered_bootstraps:
                raise ValueError('This local ticket already has a bootstrap set')
            if len(self._registered_bootstraps) >= 256:
                raise ValueError('Registered local bootstrap capacity reached')
            prepared = tuple(dict(preflight_actor_manifest(manifest, channel_sequence=1023,
                max_packet_bytes=connection.max_packet_bytes).actor_fields) for manifest in manifests)
            self._validate_actor_field_set(prepared)
            if admitted_owned_actor_channels is not None:
                dynamic = {f['channel_index'] for f in prepared if not f['actor_guid'] & 1}
                if (type(admitted_owned_actor_channels) is not tuple or len(admitted_owned_actor_channels) > 14 or
                        any(type(c) is not int or c not in dynamic for c in admitted_owned_actor_channels) or
                        len(set(admitted_owned_actor_channels)) != len(admitted_owned_actor_channels)):
                    raise ValueError('Owned reliable receipt channels must belong to this admitted dynamic set')
            if inventory_refresh_profile is not None:
                from dfserver.replication.legacy_ds_inventory_refresh import InventoryRefreshProfile
                if type(inventory_refresh_profile) is not InventoryRefreshProfile or admitted_owned_actor_channels is None:
                    raise ValueError('Inventory refresh requires the explicit admitted receipt policy')
                inventory_refresh_profile.__post_init__()
            if owner_switch_profile is not None:
                from dfserver.transport.native.legacy_ds_owner_switch import OwnerSwitchProfile
                if type(owner_switch_profile) is not OwnerSwitchProfile or admitted_owned_actor_channels is None:
                    raise ValueError('Owner switch authority requires this admission owning receipt policy')
                owner_switch_profile.__post_init__()
            if movement_profile is not None:
                from dfserver.transport.native.legacy_ds_movement import MovementProfile
                if type(movement_profile) is not MovementProfile or admitted_owned_actor_channels is None:
                    raise ValueError('Movement authority requires this admission owning receipt policy')
                movement_profile.__post_init__()
            if level_visibility_profile is not None:
                from dfserver.transport.native.legacy_ds_level_visibility import LevelVisibilityProfile
                if type(level_visibility_profile) is not LevelVisibilityProfile or admitted_owned_actor_channels is None:
                    raise ValueError('Level visibility requires this admission owning receipt policy')
                level_visibility_profile.__post_init__()
            if static_box_runtime_profile is not None:
                from dfserver.replication.static_actor_registry import StaticActorRegistryProfile
                if (type(static_box_runtime_profile) is not StaticActorRegistryProfile
                        or static_box_runtime_profile.ticket is not ticket or admitted_owned_actor_channels is None
                        or any(m not in manifests for m in static_box_runtime_profile.manifests)):
                    raise ValueError('The static box registry must use this exact admitted manifest namespace')
                static_box_runtime_profile.__post_init__()
            preflight_actor_content_plans(prepared, post_open_actor_contents,
                initial_channel_sequence=1023, max_packet_bytes=connection.max_packet_bytes)
            self._registered_bootstraps[ticket.cookie] = {
                'ticket': ticket, 'actor_fields': prepared, 'status': 'waiting_for_join',
                'peer': None, 'generation': None, 'resolver': resolver,
                'post_open_actor_contents': tuple(dict(plan) for plan in post_open_actor_contents),
                'inventory_refresh_profile': inventory_refresh_profile,
                'owner_switch_profile': owner_switch_profile,
                'movement_profile': movement_profile,
                'level_visibility_profile': level_visibility_profile,
                'static_box_runtime_profile': static_box_runtime_profile,
                'static_box_runtime': None,
            }
            if admitted_owned_actor_channels is not None:
                self._registered_bootstraps[ticket.cookie]['admitted_owned_actor_channels'] = admitted_owned_actor_channels
            self._bootstrap_events['registered_sets'] += 1
        self._write_report()

    def set_pc_ping_profile(self, map_id, manifest, profile):
        """Owner-side opt-in tied to the exact evidenced PC manifest namespace."""
        from dfserver.replication.legacy_ds_actor_manifest import ActorManifest
        from dfserver.transport.native.legacy_ds_pc_ping_receiver import PCPingProfile
        if (type(map_id) is not int or map_id not in self._welcome_map_ids or
                type(manifest) is not ActorManifest or type(profile) is not PCPingProfile or
                manifest.class_path != profile.class_path):
            raise ValueError('PC Ping requires a qualified controller manifest and served map')
        profile.__post_init__()
        _require_pc_profile_build(manifest, profile)
        with self._lock:
            if self._registered_bootstraps or map_id in self._pc_ping_profiles:
                raise ValueError('PC Ping must be configured before issuing any local match')
            self._pc_ping_profiles[map_id] = (manifest.channel_index, manifest.actor_guid, profile)

    def set_pc_startup_profile(self, map_id, manifest, profile):
        from dfserver.replication.legacy_ds_actor_manifest import ActorManifest
        from dfserver.transport.native.legacy_ds_pc_startup_rpc import PCStartupProfile
        if (type(map_id) is not int or map_id not in self._welcome_map_ids or
                type(manifest) is not ActorManifest or type(profile) is not PCStartupProfile or
                manifest.class_path != profile.class_path):
            raise ValueError('PC startup requires a qualified controller manifest and served map')
        profile.__post_init__()
        _require_pc_profile_build(manifest, profile)
        with self._lock:
            if self._registered_bootstraps or map_id in self._pc_startup_profiles:
                raise ValueError('PC startup must be configured before issuing any local match')
            self._pc_startup_profiles[map_id] = (manifest.channel_index, manifest.actor_guid, profile)

    def set_game_state_start_profile(self, map_id, manifest, profile):
        from dfserver.replication.legacy_ds_actor_manifest import ActorManifest
        from dfserver.replication.legacy_ds_game_state_start import GameStateStartProfile
        if (type(map_id) is not int or map_id not in self._welcome_map_ids or
                type(manifest) is not ActorManifest or type(profile) is not GameStateStartProfile or
                manifest.class_path != profile.class_path or manifest.client_sha256 != profile.client_sha256):
            raise ValueError('StartPlay requires a qualified GameState manifest and served map')
        profile.__post_init__()
        if manifest.current_qualification is not None or profile.current_qualification is not None:
            from dfserver.replication.legacy_ds_current_actor_profile import require_current_actor_manifest
            if (require_current_actor_manifest(manifest) != 'GameState' or
                    manifest.current_qualification != profile.current_qualification):
                raise ValueError('Current GameState Actor and readiness sources must agree')
        with self._lock:
            if self._registered_bootstraps or map_id in self._game_state_start_profiles:
                raise ValueError('StartPlay must be configured before issuing any local match')
            self._game_state_start_profiles[map_id] = (manifest.channel_index, manifest.actor_guid, profile)

    def set_pc_restart_profile(self, map_id, pc_manifest, pawn_manifest, profile):
        """Configure future tickets' restart identities before any local match issues."""
        from dfserver.replication.legacy_ds_actor_manifest import ActorManifest, preflight_actor_manifest
        from dfserver.transport.native.legacy_ds_pc_restart_rpc import PCRestartProfile
        from dfserver.replication.legacy_ds_scalar_serializers import SHIPPING_SHA256
        if (type(map_id) is not int or map_id not in self._welcome_map_ids or
                type(pc_manifest) is not ActorManifest or type(pawn_manifest) is not ActorManifest or
                type(profile) is not PCRestartProfile or pc_manifest.class_path != profile.class_path or
                pawn_manifest.class_path != '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C' or
                pc_manifest.level_path != pawn_manifest.level_path or
                pc_manifest.channel_index == pawn_manifest.channel_index or
                pc_manifest.actor_guid == pawn_manifest.actor_guid or
                (pc_manifest.connection_network_version, pc_manifest.archive_network_version) !=
                (pawn_manifest.connection_network_version, pawn_manifest.archive_network_version)):
            raise ValueError('Restart requires distinct source-qualified PC/Pawn manifests in the same served level')
        profile.__post_init__()
        _require_pc_profile_build(pc_manifest, profile)
        if profile.current_qualification is None:
            if pawn_manifest.client_sha256 != SHIPPING_SHA256 or pawn_manifest.current_qualification is not None:
                raise ValueError('Historical restart requires its historical Pawn build')
        else:
            from dfserver.replication.legacy_ds_current_actor_profile import require_current_actor_manifest
            if (require_current_actor_manifest(pawn_manifest) != 'Pawn' or
                    pawn_manifest.current_qualification != pc_manifest.current_qualification):
                raise ValueError('Current restart requires the same qualified PC/Pawn sources')
        with self._lock:
            if self._registered_bootstraps or map_id in self._pc_restart_profiles:
                raise ValueError('Restart must be configured before issuing any local match')
            connection = self._handshake.packet_ack_probe if self._handshake else None
            if not isinstance(connection, LegacyDSControlConnection):
                raise ValueError('Restart requires the admitted native connection')
            for manifest in (pc_manifest, pawn_manifest):
                preflight_actor_manifest(manifest, channel_sequence=1023,
                                         max_packet_bytes=connection.max_packet_bytes)
            if (map_id not in self._pc_startup_profiles or map_id not in self._game_state_start_profiles or
                    self._pc_startup_profiles[map_id][:2] != (pc_manifest.channel_index, pc_manifest.actor_guid)):
                raise ValueError('Restart requires the same configured startup PC and GameState readiness profiles')
            if (self._pc_startup_profiles[map_id][2].current_qualification != profile.current_qualification or
                    self._game_state_start_profiles[map_id][2].current_qualification != pc_manifest.current_qualification):
                raise ValueError('Restart, startup and readiness must share the same source build')
            self._pc_restart_profiles[map_id] = (pc_manifest.channel_index, pc_manifest.actor_guid,
                                                pawn_manifest.actor_guid, profile)
            self._pc_restart_manifests[map_id] = (pc_manifest, pawn_manifest)

    def set_pc_view_target_profile(self, map_id, pc_manifest, pawn_manifest, profile):
        """Configure an explicit local owned-Pawn camera policy for future tickets."""
        from dfserver.replication.legacy_ds_actor_manifest import ActorManifest, preflight_actor_manifest
        from dfserver.transport.native.legacy_ds_pc_view_target_rpc import PCViewTargetProfile
        if (type(map_id) is not int or map_id not in self._welcome_map_ids or
                type(pc_manifest) is not ActorManifest or type(pawn_manifest) is not ActorManifest or
                type(profile) is not PCViewTargetProfile):
            raise ValueError('View target requires typed source-qualified PC/Pawn manifests and profile')
        profile.__post_init__()
        _require_pc_profile_build(pc_manifest, profile)
        with self._lock:
            if self._registered_bootstraps or map_id in self._pc_view_target_profiles:
                raise ValueError('View target must be configured before issuing any local match')
            restart = self._pc_restart_profiles.get(map_id)
            if (restart is None or self._pc_restart_manifests.get(map_id) != (pc_manifest, pawn_manifest) or
                    profile.class_path != restart[3].class_path or
                    profile.exclusive_index_maximum != restart[3].exclusive_index_maximum or
                    profile.object_binding != restart[3].object_binding):
                raise ValueError('View target must reuse the exact configured restart PC/Pawn namespace')
            connection = self._handshake.packet_ack_probe if self._handshake else None
            if not isinstance(connection, LegacyDSControlConnection):
                raise ValueError('View target requires the admitted native connection')
            for manifest in (pc_manifest, pawn_manifest):
                preflight_actor_manifest(manifest, channel_sequence=1023,
                                         max_packet_bytes=connection.max_packet_bytes)
            self._pc_view_target_profiles[map_id] = profile

    def set_pc_rotation_profile(self, map_id, pc_manifest, pawn_manifest, profile):
        from dfserver.transport.native.legacy_ds_pc_rotation_rpc import PCRotationProfile, build_pc_rotation
        if type(profile) is not PCRotationProfile:
            raise ValueError('A source-qualified controller rotation profile is required')
        profile.__post_init__()
        _require_pc_profile_build(pc_manifest, profile)
        with self._lock:
            restart = self._pc_restart_profiles.get(map_id)
            if (self._registered_bootstraps or map_id in self._pc_rotation_profiles or
                    restart is None or self._pc_restart_manifests.get(map_id) != (pc_manifest, pawn_manifest) or
                    profile.class_path != restart[3].class_path or
                    profile.exclusive_index_maximum != restart[3].exclusive_index_maximum):
                raise ValueError('Rotation requires the exact configured restart PC/Pawn before any local match')
            connection = self._handshake.packet_ack_probe if self._handshake else None
            if not isinstance(connection, LegacyDSControlConnection):
                raise ValueError('Rotation requires the admitted native connection')
            bunch = build_pc_rotation(channel_index=pc_manifest.channel_index, channel_sequence=1023,
                profile=profile, rotation=pawn_manifest.rotation, reset_camera=True)
            from dfserver.transport.native.legacy_ds_wire_codec import WirePacket, encode_observed_application
            encode_observed_application(WirePacket(16383, 16383, (0xffffffff,), False, 0, None, (bunch,), 0),
                max_packet_bytes=connection.max_packet_bytes, received_by_server=False)
            self._pc_rotation_profiles[map_id] = profile

    def set_pc_hud_profile(self, map_id, pc_manifest, pawn_manifest, profile, class_guid):
        from dfserver.transport.native.legacy_ds_pc_hud_rpc import PCHUDProfile, build_pc_hud
        if type(profile) is not PCHUDProfile:
            raise ValueError('The source-qualified cooked HUD profile is required')
        profile.__post_init__()
        with self._lock:
            restart = self._pc_restart_profiles.get(map_id)
            if (self._registered_bootstraps or map_id in self._pc_hud_profiles or restart is None or
                    self._pc_restart_manifests.get(map_id) != (pc_manifest, pawn_manifest) or
                    profile.class_path != restart[3].class_path or
                    profile.exclusive_index_maximum != restart[3].exclusive_index_maximum):
                raise ValueError('HUD requires the configured PC/Pawn namespace before any local match')
            bindings = {b.guid: b.full_path for b in pc_manifest.path_bindings}
            if bindings.get(class_guid) != profile.hud_class_path:
                raise ValueError('The HUD class must be in the actual PC export manifest')
            connection = self._handshake.packet_ack_probe if self._handshake else None
            if not isinstance(connection, LegacyDSControlConnection):
                raise ValueError('HUD requires the admitted native connection')
            bunch = build_pc_hud(channel_index=pc_manifest.channel_index, channel_sequence=1023,
                profile=profile, class_guid=class_guid, reference_resolved=True, exports_acknowledged=True)
            from dfserver.transport.native.legacy_ds_wire_codec import WirePacket, encode_observed_application
            encode_observed_application(WirePacket(16383, 16383, (0xffffffff,), False, 0, None, (bunch,), 0),
                max_packet_bytes=connection.max_packet_bytes, received_by_server=False)
            self._pc_hud_profiles[map_id] = (profile, class_guid)

    def request_pc_restart(self, map_id, *, observer_owner_sink=None):
        """Bind an owner-observed post-travel request to one current ticket generation.

        'queued' means the request gate was stored, not that poll sent the RPC.
        No matching admitted/queued peer returns 'pending' without arming future
        tickets. Ambiguous current registrations are rejected rather than guessed.
        """
        if type(map_id) is not int or map_id not in self._pc_restart_profiles:
            raise ValueError('Restart request requires an explicitly configured served map')
        if observer_owner_sink is not None and (type(observer_owner_sink) is not list or observer_owner_sink):
            raise ValueError('Restart observer owner requires one empty private sink')
        with self._lock:
            self._handshake._expire(time.perf_counter() - self._started_at)
            self._expire_registered_bootstraps_locked()
            connection = self._handshake.packet_ack_probe
            if not isinstance(connection, LegacyDSControlConnection):
                raise ValueError('Restart requires the admitted native connection')
            matches = []
            for cookie, registration in self._registered_bootstraps.items():
                ticket = registration['ticket']
                if ticket.map_id != map_id or registration['status'] != 'queued':
                    continue
                peer, generation = registration['peer'], registration['generation']
                state = connection.control_peers.get(peer)
                if (not self._admissions.is_active(ticket) or connection.ticket_peers.get(cookie) != peer or
                        generation is None or generation.verified_at is None or
                        self._handshake.pending.get(peer) is not generation or peer not in connection.peers or
                        state is None or state.ticket is not ticket or state.client_closed or
                        not state.client_join_observed):
                    continue
                expected = self._pc_restart_profiles[map_id]
                if ((state.pc_restart_channel, state.pc_restart_actor_guid,
                     state.pc_restart_pawn_guid, state.pc_restart_profile) != expected or
                        state.pc_restart_ticket is not ticket):
                    raise ValueError('Restart registration differs from this ticket PC/Pawn profile')
                fields = registration['actor_fields']
                if (set(state.actor_opens) != {f['channel_index'] for f in fields} or
                        any((item := state.actor_opens.get(f['channel_index'])) is None or
                            item.actor_guid != f['actor_guid'] for f in fields)):
                    raise ValueError('Restart registration Actor namespace changed')
                matches.append((peer, state, registration))
            if not matches:
                return 'pending'
            if len(matches) != 1:
                raise ValueError('Restart requires one unambiguous current admitted ticket')
            peer, state, registration = matches[0]
            requested = state.pc_restart_requested
            connection.request_pc_restart(peer)
            if observer_owner_sink is not None:
                observer_owner_sink.append(_PCRestartObserverOwner(self, connection, registration,
                    state.ticket, registration['generation'], connection.peers[peer], peer,
                    self._pc_restart_profiles[map_id], deepcopy(registration['actor_fields']),
                    state.pc_restart_actor_namespace, state.pc_restart_content_namespace))
            if not requested and self._pc_restart_capture is None:
                self._pc_restart_capture = {
                    'ticket': state.ticket, 'generation': self._handshake.pending[peer],
                    'channel': state.pc_restart_channel, 'actor_guid': state.pc_restart_actor_guid,
                    'started_at': time.perf_counter(), 'packet_limit': 128, 'duration_seconds': 120,
                }
            return 'already_requested' if requested else 'queued'

    def pc_restart_observer_delivery_gate(self, map_id, *, owner):
        """Current request's exact full-send positive receipt; no native-read gate.

        The opaque owner is captured by request_pc_restart under this same lock.
        Missing or retired evidence waits; queued status and global counts cannot
        authorize the one-shot appearance observer. Delivery is not possession.
        """
        def waiting(condition):
            return {'status': 'waiting', 'waiting_for': (condition,)}
        with self._lock:
            if (type(owner) is not _PCRestartObserverOwner or owner.probe is not self or
                    type(map_id) is not int or owner.ticket.map_id != map_id or
                    self._handshake is None or self._admissions is None or
                    not self.listening or self._stop.is_set()):
                return waiting('current_restart_owner')
            self._handshake._expire(time.perf_counter() - self._started_at)
            self._expire_registered_bootstraps_locked()
            connection = self._handshake.packet_ack_probe
            registrations = [r for r in self._registered_bootstraps.values()
                if r['ticket'].map_id == map_id and r['status'] == 'queued' and
                self._admissions.is_active(r['ticket'])]
            if len(registrations) != 1:
                return waiting('one_current_registered_owner')
            registration = registrations[0]
            peer, generation, ticket = registration['peer'], registration['generation'], registration['ticket']
            state = connection.control_peers.get(peer) if isinstance(connection, LegacyDSControlConnection) else None
            if (connection is not owner.connection or registration is not owner.registration or
                    ticket is not owner.ticket or peer != owner.peer or generation is not owner.generation or
                    generation is None or generation.verified_at is None or not generation.echoed or
                    self._handshake.pending.get(peer) is not generation or
                    self._handshake.current_peer_for_generation(generation, ticket) != peer or
                    connection.peers.get(peer) is not owner.transport or
                    connection.ticket_peers.get(ticket.cookie) != peer or state is None or
                    state.ticket is not ticket or not state.client_join_observed or state.client_closed or
                    self._pc_restart_profiles.get(map_id) != owner.profile or
                    registration['actor_fields'] != owner.actor_fields or
                    state.pc_restart_actor_namespace != owner.actor_namespace or
                    state.pc_restart_content_namespace != owner.content_namespace):
                return waiting('current_restart_owner')
            try:
                connection._pc_restart_binding(state, peer)
                if (state.pc_restart_channel, state.pc_restart_actor_guid,
                        state.pc_restart_pawn_guid, state.pc_restart_profile) != owner.profile:
                    return waiting('current_pc_pawn_binding')
                restart = state.pc_restart
                if restart is None or not state.pc_restart_requested:
                    return waiting('pc_restart_delivery')
                from dfserver.transport.native.legacy_ds_pc_restart_rpc import build_pc_restart
                expected = build_pc_restart(channel_index=state.pc_restart_channel,
                    channel_sequence=restart.bunch.channel_sequence, profile=state.pc_restart_profile,
                    pawn_guid=state.pc_restart_pawn_guid, reference_resolved=True, exports_acknowledged=True)
                if restart.actor_guid != state.pc_restart_actor_guid or restart.bunch != expected:
                    return waiting('current_pc_pawn_binding')
            except (ValueError, TypeError, KeyError, AttributeError):
                return waiting('current_pc_pawn_binding')
            if not connection._actual_actor_delivery(restart):
                return waiting('pc_restart_delivery')
            receipt = state.pc_restart_receipt
            if (type(receipt) is not _ActualActorReceipt or receipt.actor_guid != restart.actor_guid or
                    receipt.bunch != restart.bunch or receipt.sequence not in restart.sent_packets or
                    receipt.ticket is not ticket or receipt.transport is not owner.transport or
                    receipt.generation is not generation):
                return waiting('pc_restart_own_full_send_positive_receipt')
            if not all(connection._actor_own_full_send_positive_receipt(state, item,
                    ticket=ticket, transport=owner.transport, generation=generation) for item in (
                        state.actor_opens[state.pc_restart_channel], state.actor_contents[state.pc_restart_channel],
                        state.actor_opens[state.pc_restart_pawn_channel], state.actor_contents[state.pc_restart_pawn_channel])):
                return waiting('pc_pawn_prerequisite_own_receipts')
            return {'status': 'ready', 'waiting_for': ()}

    def set_initial_actor_manifests_with_early_player_state_human_appearance_diagnostic(
            self, map_id, manifests, *, content, source_pins, resolver=None, post_open_actor_contents=()):
        """Atomically qualify/publish one fresh default-Weilong initial plan."""
        self.set_initial_actor_manifests(map_id, manifests, resolver=resolver,
            post_open_actor_contents=post_open_actor_contents,
            early_player_state_human_appearance=(content, source_pins))
        return 'configured'

    def _prepare_early_player_state_human_appearance(self, map_id, manifests, old_plans, policy, connection):
        """Pure staging under the owner lock; publish nothing on failure."""
        from dfserver.replication.legacy_ds_late_player_state_human_appearance import LatePlayerStateHumanAppearanceDiagnostic, CLASS_PATH
        if type(policy) is not tuple or len(policy) != 2:
            raise ValueError('Early PlayerState trial requires explicit content and source pins')
        content, source_pins = policy
        if (type(map_id) is not int or map_id != 2201 or type(source_pins) is not dict or
                any(type(k) is not str or type(v) is not str for k, v in source_pins.items())):
            raise ValueError('Early PlayerState trial requires the explicit sealed map scope')
        profile = LatePlayerStateHumanAppearanceDiagnostic(content, tuple(sorted(source_pins.items())))
        if (self._stop.is_set() or self._require_initial_actor_profile is not True or
                self._admissions is None or self._registered_bootstraps or
                connection.control_peers or self._admissions.summary()['issued_ticket_count'] != 0 or
                map_id in self._initial_actor_profiles or
                map_id in self._early_player_state_human_appearance_profiles):
            raise ValueError('Early PlayerState trial requires one unconfigured fresh owner')
        matches = [m for m in manifests if m.class_path == CLASS_PATH]
        if len(matches) != 1 or type(old_plans) is not tuple or len(old_plans) != 3:
            raise ValueError('Early PlayerState trial requires the complete original Actor plan')
        ps = matches[0]
        if any(p['channel_index'] == ps.channel_index for p in old_plans):
            raise ValueError('Early PlayerState trial cannot replace existing PlayerState content')
        plans = tuple(deepcopy(old_plans)) + ({'channel_index': ps.channel_index,
            'actor_guid': ps.actor_guid, 'content_blocks': (content,)},)
        if not profile.sources_current():
            raise ValueError('Early PlayerState trial sources changed')
        return plans, (ps, profile)

    def _early_player_state_request(self, ticket, registration, connection, peer, generation, fields):
        """Bind a temporary queue preflight to the exact later published owner."""
        from dfserver.replication.legacy_ds_late_player_state_human_appearance import TRIAL_OPERATOR
        from dfserver.replication.legacy_ds_early_player_state_human_appearance import namespace
        configured, ps, profile = self._early_player_state_human_appearance_profiles[ticket.map_id]
        if ticket.map_id != 2201 or type(ticket.selected_hero_id) is not int or ticket.selected_hero_id != TRIAL_OPERATOR:
            raise ValueError('Early PlayerState trial is limited to the selected Weilong operator')
        original_fields = deepcopy(registration['actor_fields'])
        kept_fields, plans = deepcopy(fields), deepcopy(registration['post_open_actor_contents'])
        manifests = configured['manifests']
        original_transport = connection.peers.get(peer)
        if original_transport is None:
            raise ValueError('Early PlayerState trial requires its original transport')
        preflight_active = [True]
        def owner(state, current_peer):
            current = connection.control_peers.get(current_peer)
            waiting = (preflight_active[0] and registration['status'] == 'waiting_for_join' and
                registration['peer'] is None and registration['generation'] is None and
                registration['actor_fields'] == original_fields and current_peer == peer)
            queued = (registration['status'] == 'queued' and registration['peer'] == current_peer and
                registration['generation'] is generation and registration['actor_fields'] == kept_fields and
                self._handshake.current_peer_for_generation(generation, ticket) == current_peer)
            return bool(self.listening and not self._stop.is_set() and (waiting or queued) and
                self._initial_actor_profiles.get(ticket.map_id) is configured and configured['manifests'] == manifests and
                configured['post_open_actor_contents'] == plans and registration['post_open_actor_contents'] == plans and
                self._registered_bootstraps.get(ticket.cookie) is registration and
                sum(r['ticket'].map_id == ticket.map_id for r in self._registered_bootstraps.values()) == 1 and
                generation is not None and generation.verified_at is not None and
                self._handshake.pending.get(current_peer) is generation and current is not None and
                current.ticket is ticket and not current.client_closed and current.client_join_observed and
                namespace(current.actor_opens) == namespace(state.actor_opens) and
                namespace(current.actor_contents) == namespace(state.actor_contents) and
                connection.ticket_peers.get(ticket.cookie) == current_peer and
                connection.peers.get(current_peer) is original_transport and
                state.ticket is ticket and state.client_join_observed and not state.client_closed and
                self._admissions.is_active(ticket) and type(current_peer) is tuple and
                len(current_peer) == 2 and current_peer[0] == '127.0.0.1' and type(current_peer[1]) is int and
                1 <= current_peer[1] <= 65535 and set(state.actor_opens) == {f['channel_index'] for f in kept_fields} and
                all(state.actor_opens[f['channel_index']].actor_guid == f['actor_guid'] for f in kept_fields))
        return (ps.channel_index, ps.actor_guid, profile, owner), preflight_active

    def queue_late_player_state_human_appearance_diagnostic(self, map_id, *, content, source_pins):
        """Explicit one-ticket Weilong trial; never arm future admissions or Uin."""
        from dfserver.replication.legacy_ds_late_player_state_human_appearance import LatePlayerStateHumanAppearanceDiagnostic, CLASS_PATH, TRIAL_OPERATOR
        from dfserver.replication.legacy_ds_actor_manifest import preflight_actor_manifest
        if (type(map_id) is not int or type(source_pins) is not dict or
                any(type(k) is not str or type(v) is not str for k, v in source_pins.items())):
            raise ValueError('PlayerState trial requires a served map and sealed source pins')
        diagnostic = LatePlayerStateHumanAppearanceDiagnostic(content, tuple(sorted(source_pins.items())))
        with self._lock:
            if map_id in self._early_player_state_human_appearance_profiles:
                raise ValueError('Early and late PlayerState trials are mutually exclusive')
            if not self.listening or self._handshake is None or self._admissions is None:
                raise ValueError('PlayerState trial requires an active local owner')
            self._handshake._expire(time.perf_counter() - self._started_at)
            self._expire_registered_bootstraps_locked()
            connection, configured = self._handshake.packet_ack_probe, self._initial_actor_profiles.get(map_id)
            if not isinstance(connection, LegacyDSControlConnection) or configured is None:
                raise ValueError('PlayerState trial has no source-matched Actor profile')
            registrations = [r for r in self._registered_bootstraps.values() if r['ticket'].map_id == map_id]
            if len(registrations) != 1:
                raise ValueError('PlayerState trial requires one current registered ticket')
            registration = registrations[0]
            ticket, peer, generation = registration['ticket'], registration['peer'], registration['generation']
            if type(ticket.selected_hero_id) is not int or ticket.selected_hero_id != TRIAL_OPERATOR:
                raise ValueError('PlayerState trial is limited to the selected Weilong operator')
            manifests = [m for m in configured['manifests'] if m.class_path == CLASS_PATH]
            if len(manifests) != 1:
                raise ValueError('PlayerState trial requires one exact PlayerState manifest')
            ps = manifests[0]
            original_manifests = configured['manifests']
            expected = dict(preflight_actor_manifest(ps, channel_sequence=1023,
                max_packet_bytes=connection.max_packet_bytes).actor_fields)
            fields = tuple(dict(f) for f in registration['actor_fields'])
            actual = [f for f in fields if f['channel_index'] == ps.channel_index]
            if len(actual) != 1 or actual[0] != expected:
                raise ValueError('PlayerState trial differs from its registered namespace')
            if registration['status'] == 'waiting_for_join':
                return 'pending'

            def current_owner(state, current_peer):
                return bool(self.listening and not self._stop.is_set() and
                    self._initial_actor_profiles.get(map_id) is configured and
                    configured['manifests'] == original_manifests and
                    self._registered_bootstraps.get(ticket.cookie) is registration and
                    sum(r['ticket'].map_id == map_id for r in self._registered_bootstraps.values()) == 1 and
                    registration['actor_fields'] == fields and registration['status'] == 'queued' and
                    registration['peer'] == current_peer and registration['generation'] is generation and
                    generation is not None and generation.verified_at is not None and
                    self._handshake.pending.get(current_peer) is generation and
                    connection.ticket_peers.get(ticket.cookie) == current_peer and current_peer in connection.peers and
                    state.ticket is ticket and state.client_join_observed and not state.client_closed and
                    self._admissions.is_active(ticket) and type(current_peer) is tuple and len(current_peer) == 2 and
                    current_peer[0] == '127.0.0.1' and type(current_peer[1]) is int and 1 <= current_peer[1] <= 65535 and
                    set(state.actor_opens) == {f['channel_index'] for f in fields} and
                    all(state.actor_opens[f['channel_index']].actor_guid == f['actor_guid'] for f in fields))

            return connection._queue_late_player_state_human_appearance(peer, profile=diagnostic,
                channel=ps.channel_index, actor_guid=ps.actor_guid, owner_check=current_owner)

    def fashion_join_owner_contract(self, map_id, *, enabled=False, source_seal=None):
        """Read-only locked contract for correlating a future local capture."""
        if type(enabled) is not bool:
            raise ValueError('Explicit Fashion diagnostic boolean required')
        if not enabled:
            return None
        from dfserver.replication.legacy_ds_fashion_async_bridge import capture_join_owner
        return capture_join_owner(self, map_id, source_seal)

    def queue_current_fashion_subobject_diagnostic(self, map_id, *, enabled=False,
            contract=None, local_proof=None, request=None, native_hero_configuration=None,
            source_seal=None, current_capture_recheck=None, retained_session=None):
        """Default-off owner API; missing local proof fails before any queue."""
        if type(enabled) is not bool:
            raise ValueError('Explicit Fashion diagnostic boolean required')
        if not enabled:
            return 'disabled'
        from dfserver.replication.legacy_ds_fashion_async_bridge import queue_current_fashion_async
        # Retained-session preflight may be slow. It owns the genuine native
        # closure and runs before the final short locked queue commit.
        return queue_current_fashion_async(self, map_id, channel=retained_session, request=request)

    @staticmethod
    def _validate_actor_field_set(prepared):
        """Validate the whole detached export graph before storing any ticket."""
        channels = [fields['channel_index'] for fields in prepared]
        actors = [fields['actor_guid'] for fields in prepared]
        if len(set(channels)) != len(channels) or len(set(actors)) != len(actors):
            raise ValueError('Initial Actors require distinct channels and Actor GUIDs')
        definitions = {}
        # Every graph here has already passed bounded manifest preflight.
        for fields in prepared:
            for root in fields['exports']:
                node = root
                while node is not None:
                    definition = (node.path, node.outer.guid if node.outer else 0, node.checksum)
                    if node.guid in definitions and definitions[node.guid] != definition:
                        raise ValueError('Initial Actors contain conflicting static GUID definitions')
                    definitions[node.guid] = definition
                    node = node.outer

    def _resolved_actor_field_set(self, ticket, registration, connection, state):
        """Validate a detached result of the private, per-Join producer.

        The normal bunch builder bounds every graph before the cross-Actor walk.
        The connection's batch queue separately reserves the complete packets and
        rolls back all queue state if any Actor fails. No producer is a network API.
        """
        from dfserver.replication.legacy_ds_actor_bunch import build_initial_actor_bunch

        resolver = registration['resolver']
        profile = self._initial_actor_profiles.get(ticket.map_id)
        if profile and profile.get('room_capacity') is not None:
            roster = self._admissions.active_room_tickets(ticket)
            if not roster or len(roster) > profile['room_capacity'] or not any(t is ticket for t in roster):
                raise ValueError('The actual local room exceeds its qualified participant subset')
        if resolver is None:
            return registration['actor_fields']
        resolved = resolver(ticket, deepcopy(registration['actor_fields']))
        if (type(resolved) is not tuple or not 1 <= len(resolved) <= 16 or
                any(type(fields) is not dict for fields in resolved)):
            raise ValueError('The bootstrap resolver requires a bounded tuple of Actor dictionaries')
        for fields in resolved:
            try:
                build_initial_actor_bunch(channel_sequence=state.initial_actor_sequence,
                    max_packet_bytes=connection.max_packet_bytes, **fields)
            except (TypeError, KeyError, AttributeError) as error:
                raise ValueError('The bootstrap resolver returned invalid Actor fields') from error
        self._validate_actor_field_set(resolved)
        return deepcopy(resolved)

    def _expire_registered_bootstraps_locked(self):
        connection = self._handshake.packet_ack_probe if self._handshake else None
        closed_tickets = ({id(state.ticket) for state in connection.control_peers.values()
                           if state.client_closed and state.ticket is not None}
                          if isinstance(connection, LegacyDSControlConnection) else set())
        for cookie, registration in list(self._registered_bootstraps.items()):
            if not self._admissions.is_active(registration['ticket']):
                if registration['status'] == 'waiting_for_join':
                    self._bootstrap_events['expired_before_join'] += 1
                self._release_admission_sources_locked(registration['ticket'])
                del self._registered_bootstraps[cookie]
            elif (registration['status'] in ('waiting_for_join', 'queued') and
                    id(registration['ticket']) in closed_tickets):
                registration['status'] = 'client_closed'
                self._release_admission_sources_locked(registration['ticket'])
                self._bootstrap_events['client_closed_sets'] += 1

    def _queue_registered_bootstraps_locked(self):
        if self._admissions is None:
            return
        self._expire_registered_bootstraps_locked()
        connection = self._handshake.packet_ack_probe
        if not isinstance(connection, LegacyDSControlConnection):
            return
        for cookie, registration in self._registered_bootstraps.items():
            if registration['status'] != 'waiting_for_join':
                continue
            ticket = registration['ticket']
            peer = connection.ticket_peers.get(cookie)
            if peer is None:
                continue
            state = connection.control_peers.get(peer)
            generation = self._handshake.pending.get(peer)
            if (state is None or state.client_closed or not state.client_join_observed or state.ticket is not ticket or
                    peer not in connection.peers or generation is None or generation.verified_at is None):
                continue
            early_preflight = None
            try:
                resolved = self._resolved_actor_field_set(ticket, registration, connection, state)
                if not self._admissions.is_active(ticket):
                    raise ValueError('The bootstrap ticket expired during resolution')
                if ticket.map_id in self._early_player_state_human_appearance_profiles:
                    early, early_preflight = self._early_player_state_request(
                        ticket, registration, connection, peer, generation, resolved)
                    connection.queue_actor_opens(peer, resolved,
                        post_open_actor_contents=registration['post_open_actor_contents'],
                        early_player_state_human_appearance=early)
                else:
                    connection.queue_actor_opens(peer, resolved,
                        post_open_actor_contents=registration['post_open_actor_contents'])
                if ticket.map_id in self._pc_ping_profiles:
                    connection.set_pc_ping_profile(peer, *self._pc_ping_profiles[ticket.map_id])
                if ticket.map_id in self._pc_startup_profiles:
                    connection.set_pc_startup_profile(peer, *self._pc_startup_profiles[ticket.map_id])
                if ticket.map_id in self._game_state_start_profiles:
                    connection.set_game_state_start_profile(peer, *self._game_state_start_profiles[ticket.map_id])
                if ticket.map_id in self._pc_restart_profiles:
                    connection.set_pc_restart_profile(peer, *self._pc_restart_profiles[ticket.map_id])
                if ticket.map_id in self._pc_view_target_profiles:
                    connection.set_pc_view_target_profile(peer, self._pc_view_target_profiles[ticket.map_id])
                if ticket.map_id in self._pc_hud_profiles:
                    connection.set_pc_hud_profile(peer, *self._pc_hud_profiles[ticket.map_id])
                if ticket.map_id in self._pc_rotation_profiles:
                    pawn_guid = self._pc_restart_profiles[ticket.map_id][2]
                    pawns = [f for f in resolved if f['actor_guid'] == pawn_guid]
                    if len(pawns) != 1:
                        raise ValueError('Controller rotation requires the actual resolved Pawn')
                    connection.set_pc_rotation_profile(peer, self._pc_rotation_profiles[ticket.map_id],
                                                       pawns[0].get('rotation'))
                if 'admitted_owned_actor_channels' in registration:
                    connection.enable_admitted_actor_receipts(peer,
                        owned_actor_channels=registration['admitted_owned_actor_channels'])
                if registration.get('inventory_refresh_profile') is not None:
                    connection.set_inventory_refresh_profile(peer, registration['inventory_refresh_profile'])
                if registration.get('owner_switch_profile') is not None:
                    connection.set_owner_switch_profile(peer, registration['owner_switch_profile'])
                if registration.get('movement_profile') is not None:
                    connection.set_movement_profile(peer, registration['movement_profile'])
                if registration.get('level_visibility_profile') is not None:
                    connection.set_level_visibility_profile(peer, registration['level_visibility_profile'])
            except (ValueError, OSError):
                if early_preflight is not None:
                    early_preflight[0] = False
                registration['status'] = 'rejected'
                self._release_admission_sources_locked(ticket)
                self._bootstrap_events['actor_set_precondition_rejected'] += 1
                continue
            registration.update(actor_fields=resolved, status='queued', peer=peer, generation=generation)
            if early_preflight is not None:
                early_preflight[0] = False
            self._bootstrap_events['queued_sets'] += 1

    def _rebind_registered_bootstraps_locked(self, old_peer, new_peer):
        """Follow an authenticated move of the exact existing ticket generation.

        The caller holds the same lock as handshake validation and transmission.
        A new handshake or an address alone must never inherit queued Actors.
        """
        if old_peer is None or old_peer == new_peer or self._handshake is None:
            return
        connection = self._handshake.packet_ack_probe
        if not isinstance(connection, LegacyDSControlConnection):
            return
        generation = self._handshake.pending.get(new_peer)
        state = connection.control_peers.get(new_peer)
        if generation is None or state is None:
            return
        ticket = state.ticket
        if self._handshake.current_peer_for_generation(generation, ticket) != new_peer:
            return
        for registration in self._registered_bootstraps.values():
            if (registration['status'] == 'queued' and registration['peer'] == old_peer and
                    registration['generation'] is generation and registration['ticket'] is ticket):
                runtime = registration.get('static_box_runtime')
                if runtime is not None:
                    try:
                        runtime.rebind_authenticated_peer(old_peer, new_peer)
                    except (ValueError, OSError):
                        registration['static_box_runtime_state'] = 'refused'
                        registration['static_box_runtime'] = None
                        self._bootstrap_events['static_box_reference_runtime_rebind_refused'] += 1
                registration['peer'] = new_peer
                self._bootstrap_events['authenticated_peer_rebinds'] += 1

    def _pump_static_box_runtimes_locked(self):
        """Route committed receipts under the same admission/network owner lock."""
        connection = self._handshake.packet_ack_probe if self._handshake else None
        if not isinstance(connection, LegacyDSControlConnection) or self._admissions is None:
            return
        for registration in self._registered_bootstraps.values():
            profile = registration.get('static_box_runtime_profile')
            if (profile is None or registration['status'] != 'queued'
                    or registration.get('static_box_runtime_state') == 'refused'
                    or not self._admissions.is_active(registration['ticket'])):
                continue
            peer = registration['peer']
            state, transport = connection.control_peers.get(peer), connection.peers.get(peer)
            generation = registration['generation']
            if (state is None or state.ticket is not registration['ticket'] or state.client_closed
                    or connection._local_stage_owner(peer, state, transport) is not generation):
                continue
            runtime = registration.get('static_box_runtime')
            if runtime is None:
                try:
                    connection._admitted_actor_receipt_binding(state, state, peer, transport, generation)
                except ValueError:
                    # Own full-send positive receipts may still be pending.
                    continue
                try:
                    runtime = profile.create(connection, peer)
                except (ValueError, OSError):
                    registration['static_box_runtime_state'] = 'refused'
                    self._bootstrap_events['static_box_reference_runtime_install_refused'] += 1
                    continue
                registration['static_box_runtime'] = runtime
                registration['static_box_runtime_state'] = 'installed_reference_runtime'
                self._bootstrap_events['static_box_reference_runtime_installed'] += 1
            try:
                outcomes = runtime.pump()
            except (ValueError, OSError):
                registration['static_box_runtime_state'] = 'refused'
                registration['static_box_runtime'] = None
                self._bootstrap_events['static_box_reference_runtime_owner_or_source_refused'] += 1
                continue
            for outcome in outcomes:
                self._bootstrap_events[outcome] += 1

    def start(self):
        if self._threads:
            raise RuntimeError('Probe already started')
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_persistence_worker()
        self._write_report()
        for target in (self._accept_tcp, self._receive_udp):
            thread = threading.Thread(target=target, daemon=True)
            if target == self._receive_udp:
                self._udp_receive_thread = thread
                self._udp_receive_state = 'starting'
            thread.start()
            self._threads.append(thread)
        self._write_report()
        return self

    def close(self):
        self._stop.set()
        bridge = getattr(self, '_fashion_async_bridge', None)
        if bridge is not None:
            bridge.close_outside_lock()
        self._tcp.close()
        self._udp.close()
        for thread in self._threads:
            thread.join(timeout=3)
        with self._lock:
            self._release_admission_sources_locked(closing=True)
        self._ensure_persistence_worker()
        with self._persistence_condition:
            if not self._persistence_stop:
                self._persistence_stop = True
                self._report_requested += 1
            target = self._report_requested
            self._persistence_condition.notify_all()
        self._wait_persistence(target, 3)
        # A failed write is still a completed task; do not wait again after
        # the bounded flush, and do not require success merely to reap it.
        with self._persistence_condition:
            finished = (self._report_completed >= target and not self._persistence_queue
                        and not self._persistence_busy)
        self._persistence_thread.join(timeout=3 if finished else 0)

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()

    @property
    def persistence_status(self):
        with self._lock:
            return self._persistence_status_locked()

    def _persistence_status_locked(self):
        return {'state': self._persistence_state,
                'queue_limit': self.max_packets + (128 if self._pc_restart_capture else 0),
                'pending_records': sum(r.get('persistence') == 'pending'
                    for r in self._records + self._pc_restart_records),
                'failed_records': sum(r.get('persistence') == 'failed'
                    for r in self._records + self._pc_restart_records),
                'errors': dict(self._persistence_errors),
                'failure': (self._persistence_failure.copy()
                            if self._persistence_failure is not None else None)}

    def _ensure_persistence_worker(self):
        with self._persistence_condition:
            if self._persistence_thread is None:
                thread = threading.Thread(target=self._persist, daemon=True)
                self._persistence_thread = thread
                thread.start()

    def _wait_persistence(self, target, timeout):
        with self._persistence_condition:
            finished = self._persistence_condition.wait_for(
                lambda: (self._report_completed >= target and not self._persistence_queue
                         and not self._persistence_busy) or
                        not self._persistence_thread.is_alive(), timeout=timeout)
            return bool(finished and self._report_completed >= target and
                        not self._persistence_queue and not self._persistence_busy and
                        not self._persistence_has_failure)

    def flush(self, *, timeout=3):
        """Bounded wait for queued raw files and the newest requested report."""
        if type(timeout) not in (int, float) or not 0 <= timeout <= 30:
            raise ValueError('A bounded nonnegative persistence timeout is required')
        self._ensure_persistence_worker()
        with self._persistence_condition:
            if self._persistence_stop:
                target = self._report_requested
            else:
                self._report_requested += 1
                target = self._report_requested
                self._persistence_condition.notify_all()
        return self._wait_persistence(target, timeout)

    def _write_report(self):
        """Coalesce snapshots; UDP/TCP workers never wait for disk IO."""
        self._ensure_persistence_worker()
        with self._persistence_condition:
            if self._persistence_stop:
                target = self._report_requested
            else:
                self._report_requested += 1
                target = self._report_requested
                self._persistence_condition.notify_all()
        if not getattr(self._io_context, 'network_worker', False):
            self._wait_persistence(target, 3)

    def _persistence_error(self, phase, error):
        code = getattr(error, 'winerror', None) or getattr(error, 'errno', None)
        code = code if type(code) is int else None
        with self._lock:
            self._persistence_state = 'failed'
            self._persistence_errors[phase + ':' + type(error).__name__ + ':' + str(code)] += 1
            self._persistence_failure = {'phase': phase, 'error_type': type(error).__name__,
                                         'error_code': code}
        with self._persistence_condition:
            self._persistence_has_failure = True

    def _persist(self):
        with self._lock:
            self._persistence_state = 'running'
        while True:
            with self._persistence_condition:
                self._persistence_condition.wait_for(lambda: self._persistence_queue or
                    self._report_requested > self._report_completed or self._persistence_stop)
                self._persistence_busy = True
                item = self._persistence_queue.popleft() if self._persistence_queue else None
                target = self._report_requested
                final = self._persistence_stop and item is None and not self._persistence_queue
            if item is not None:
                number, name, payload, record = item
                try:
                    path = self.capture_dir / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    written = path.write_bytes(payload)
                    if written != len(payload):
                        raise OSError('Incomplete bounded packet write')
                except Exception as error:
                    self._persistence_error('packet', error)
                    status = 'failed'
                else:
                    status = 'written'
                with self._lock:
                    record['persistence'] = status
            else:
                if final:
                    with self._lock:
                        if self._persistence_state != 'failed':
                            self._persistence_state = 'stopped'
                try:
                    self._publish_report()
                except Exception as error:
                    self._persistence_error('report', error)
                with self._persistence_condition:
                    self._report_completed = max(self._report_completed, target)
            with self._persistence_condition:
                self._persistence_busy = False
                self._persistence_condition.notify_all()
            if final:
                return

    def _publish_report(self):
        with self._report_lock:
            # Snapshot after serializing writers so an older TCP snapshot
            # cannot overwrite a newer UDP snapshot (or the final close).
            with self._lock:
                private_receipts = self._admitted_receipt_snapshot_locked()
                report = {'kind': 'local_game_server_transport_probe',
                          'address': '127.0.0.1', 'port': self.port,
                          'listening': self.listening,
                          'udp_receive_state': self._udp_receive_state,
                          'udp_receive_thread_alive': (self._udp_receive_thread is not None and
                                                       self._udp_receive_thread.is_alive()),
                          'udp_receive_errors': dict(self._udp_receive_errors),
                          'udp_receive_failure': (self._udp_receive_failure.copy()
                              if self._udp_receive_failure is not None else None),
                          'source_cycle_processing': {phase: {
                              key: round(value, 6) if type(value) is float else value
                              for key, value in metrics.items()}
                              for phase, metrics in self._source_cycle_processing.items()},
                          'gameplay_server_implemented': False,
                          'packet_limit': self.max_packets,
                          'tcp_connections_accepted': self._tcp_accepted,
                          'tcp_accept_samples': list(self._tcp_accept_samples),
                          'handshake_probe': (self._handshake.summary() if self._handshake else {'enabled': False}),
                          'handshake_datagrams_sent': self._handshake_sent,
                          'empty_packet_ack_datagrams_sent': self._packet_ack_sent,
                          'native_control_datagrams_sent': self._control_sent,
                          'transport_keepalive_datagrams_sent': self._transport_keepalive_sent,
                          'initial_actor_open_datagrams_sent': self._actor_open_sent,
                          'post_open_actor_content_datagrams_sent': self._actor_content_sent,
            'player_state_human_appearance_datagrams_sent': self._player_state_human_appearance_sent,
            **({'early_player_state_human_appearance_datagrams_sent': self._early_player_state_human_appearance_sent}
               if self._early_player_state_human_appearance_profiles else {}),
                          'pc_restart_rpc_datagrams_sent': self._pc_restart_sent,
                          'pc_view_target_rpc_datagrams_sent': self._pc_view_target_sent,
                          'pc_rotation_rpc_datagrams_sent': self._pc_rotation_sent,
                          'pc_hud_rpc_datagrams_sent': self._pc_hud_sent,
                          'pc_restart_packet_capture': {
                              'armed': self._pc_restart_capture is not None,
                              'packet_limit': 128, 'duration_seconds': 120,
                              'scope': 'current_requested_pc_actor_channel_or_ack_only',
                              'skips': dict(self._pc_restart_capture_skips),
                              'records': [record.copy() for record in self._pc_restart_records
                                          if record.get('persistence') == 'written'],
                              'gameplay_handled': False,
                              'native_possession_verified': False,
                          },
                          'initial_actor_bootstrap': {
                              'configured_map_profiles': len(self._initial_actor_profiles),
                              'registered_sets': len(self._registered_bootstraps),
                              'waiting_for_join': sum(item['status'] == 'waiting_for_join'
                                  for item in self._registered_bootstraps.values()),
                              'events': dict(self._bootstrap_events),
                              'source_lease_cleanup_errors': [
                                  {'error_type': error_type, 'count': count}
                                  for error_type, count in sorted(self._source_cleanup_errors.items())],
                              'local_room_world_states': [deepcopy(r['local_world_state'])
                                  for r in self._registered_bootstraps.values() if 'local_world_state' in r],
                              'native_spawn_verified': False,
                          },
                          'packet_persistence': self._persistence_status_locked(),
                          **({'admitted_receipt_capture': self._admitted_receipt_summary_locked()}
                             if private_receipts is not None else {}),
                          # A published path always refers to a fully written raw file.
                          'records': [record.copy() for record in self._records
                                      if record.get('persistence') == 'written']}
            if private_receipts is not None:
                private_temporary = self.capture_dir / 'admitted-receipt-private.json.tmp'
                private_temporary.write_text(json.dumps(private_receipts, separators=(',', ':')) + '\n',
                    encoding='ascii')
                with private_temporary.open('r+b') as stream:
                    stream.flush()
                    os.fsync(stream.fileno())
                private_temporary.replace(self.capture_dir / 'admitted-receipt-private.json')
            temporary = self.capture_dir / 'report.json.tmp'
            temporary.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
            with temporary.open('r+b') as stream:
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.capture_dir / 'report.json')

    def _admitted_receipt_summary_locked(self):
        capture = self._admitted_receipt_capture
        if capture is None:
            return None
        return {'enabled': True, 'epoch': capture['epoch'], 'packet_limit': 3 * ADMITTED_CAPTURE_SLOTS,
            'raw_byte_limit': 3 * ADMITTED_CAPTURE_SLOTS * (capture['packet_byte_limit']),
            'phase_seconds': ADMITTED_CAPTURE_PHASE_SECONDS,
            'observed_packets': capture['observed_packets'],
            'events': dict(capture['events']), 'rejection_reasons': dict(capture['rejection_reasons']),
            'recent_packets': len(capture['recent']), 'rejected_packets': len(capture['rejected']),
            'phase_packets': len(capture['phase']), 'private_payloads_in_report': False}

    def _admitted_receipt_snapshot_locked(self):
        capture = self._admitted_receipt_capture
        if capture is None:
            return None
        records = []
        for sample, rows in (('recent', capture['recent']), ('rejected', capture['rejected']),
                ('phase', capture['phase'].values())):
            for row in rows:
                records.append(dict(row, sample=sample))
        return dict(self._admitted_receipt_summary_locked(), kind='private_admitted_receipt_diagnostics',
            records=sorted(records, key=lambda row: (row['number'], row['sample'])))

    def _record_admitted_receipt_locked(self, payload, peer, event, owner, *, now=None):
        """Observe only this admitted owner; this never changes transport policy.

        The report worker coalesces atomic private snapshots. Three fixed rings
        retain recent receives, recent rejections and a sample across 32 minutes.
        No raw-packet work is added to the persistence queue or public report.
        """
        if (not self._require_initial_actor_profile or self._stop.is_set() or
                self._handshake is None or type(owner) is not tuple or len(owner) != 3):
            return
        connection = self._handshake.packet_ack_probe
        if not isinstance(connection, LegacyDSControlConnection):
            return
        generation, ticket, transport = owner
        state = connection.control_peers.get(peer)
        lease = getattr(state, 'admitted_actor_receipt_lease', None)
        if (state is None or not state.admitted_actor_reliable_receipts or
                state.ticket is not ticket or connection.peers.get(peer) is not transport or
                self._handshake.pending.get(peer) is not generation or
                getattr(lease, 'ticket', None) is not ticket or
                getattr(lease, 'generation', None) is not generation or
                getattr(lease, 'transport', None) is not transport or getattr(lease, 'peer', None) != peer):
            return
        current = self._actual_application_send_owner_locked(peer)
        closed = event == 'control_client_close_consumed' and state.client_closed
        if not closed and (current is None or any(a is not b for a, b in zip(owner, current))):
            return
        if (type(payload) is not bytes or not 8 <= len(payload) <= connection.max_packet_bytes + 8):
            return
        if now is None:
            now = time.perf_counter() - self._started_at
        if type(now) not in (int, float) or not 0 <= now < float('inf'):
            return
        capture = self._admitted_receipt_capture
        if capture is None or any(a is not b for a, b in zip(owner, capture['owner'])):
            self._admitted_receipt_capture_epoch += 1
            capture = {'owner': owner, 'epoch': self._admitted_receipt_capture_epoch,
                'packet_byte_limit': connection.max_packet_bytes + 8,
                'observed_packets': 0, 'events': Counter(), 'rejection_reasons': Counter(),
                'recent': deque(maxlen=ADMITTED_CAPTURE_SLOTS),
                'rejected': deque(maxlen=ADMITTED_CAPTURE_SLOTS), 'phase': {}}
            self._admitted_receipt_capture = capture
        event = event if event in _ADMITTED_CAPTURE_EVENTS else 'other'
        capture['observed_packets'] = min(capture['observed_packets'] + 1, 0x7fffffff)
        capture['events'][event] = min(capture['events'][event] + 1, 0x7fffffff)
        witness = state.admitted_actor_last_rejection
        rejected = event.endswith('_rejected')
        reason = (witness[2] if event == 'admitted_actor_reliable_packet_rejected' and
            witness is not None and witness[0] == transport.in_sequence and
            witness[2] in ADMITTED_RECEIPT_REJECTION_CODES else
            event if rejected else 'none')
        if rejected:
            capture['rejection_reasons'][reason] = min(capture['rejection_reasons'][reason] + 1, 0x7fffffff)
        record = {'number': capture['observed_packets'], 'elapsed_seconds': round(now, 6),
            'direction': 'received', 'event': event, 'reason_code': reason,
            'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
            'payload_base64': base64.b64encode(payload).decode('ascii')}
        if event == 'application_sequence_rejected':
            from dfserver.transport.native.legacy_ds_packet_ack_probe import MASK
            from dfserver.transport.native.legacy_ds_wire_codec import decode_observed_application
            try:
                packet = decode_observed_application(payload[8:],
                    max_packet_bytes=connection.max_packet_bytes, received_by_server=True)
            except ValueError:
                pass
            else:
                # Rejected sequence gates return before mutating these cursors.
                delta = (packet.sequence - transport.in_sequence) & MASK
                ack_delta = (packet.acknowledged_sequence - transport.acknowledged_out_sequence) & MASK
                sent_delta = (transport.out_sequence - transport.acknowledged_out_sequence) & MASK
                record['sequence_state'] = {
                    'in_sequence': transport.in_sequence,
                    'next_out_sequence': transport.out_sequence,
                    'acknowledged_out_sequence': transport.acknowledged_out_sequence,
                    'receive_delta': delta, 'ack_delta': ack_delta, 'sent_delta': sent_delta,
                    'outside_normal_receive_window': not 1 <= delta <= 32,
                    'ack_outside_prepared_window': ack_delta >= sent_delta,
                    'actual_send_count': len(state.actual_application_sends),
                    'last_successful_send_at': state.last_successful_application_send_at,
                    'positive_actual_send_receipt': connection._actual_successful_receipt_matches(
                        state, packet, transport, generation),
                }
        capture['recent'].append(record)
        if rejected:
            capture['rejected'].append(record)
        bucket = int(now // ADMITTED_CAPTURE_PHASE_SECONDS)
        slot = bucket % ADMITTED_CAPTURE_SLOTS
        if capture['phase'].get(slot, {}).get('phase_bucket') != bucket:
            capture['phase'][slot] = dict(record, phase_bucket=bucket)

    def _record(self, transport, payload, *, direction='received', peer=None):
        if not payload:
            return
        if transport == 'udp':
            self._record_pc_restart_packet(payload, direction=direction, peer=peer)
        with self._lock:
            if self._stop.is_set() or len(self._records) >= self.max_packets:
                return
            number = len(self._records) + 1
            name = f'{number:02d}-{transport}.bin'
            record = {
                'number': number, 'transport': transport, 'bytes': len(payload),
                'direction': direction,
                'sha256': hashlib.sha256(payload).hexdigest(),
                'captured_at_utc': datetime.now(timezone.utc).isoformat(),
                'elapsed_seconds': round(time.perf_counter() - self._started_at, 6),
                'private_packet_file': name,
                'persistence': 'pending',
            }
            # Retain the loopback endpoint so replay can distinguish a new
            # socket from a lost handshake on an existing socket. This is
            # packet metadata only; it never authorizes or rebinds a peer.
            if (transport == 'udp' and isinstance(peer, tuple) and len(peer) == 2 and
                    peer[0] == '127.0.0.1' and type(peer[1]) is int and 1 <= peer[1] <= 65535):
                record['peer_port'] = peer[1]
            self._records.append(record)
            # Total accepted records and this queue are both bounded by max_packets.
            with self._persistence_condition:
                if self._stop.is_set() or self._persistence_stop:
                    self._records.pop()
                    return
                self._persistence_queue.append((number, name, payload, record))
                self._persistence_condition.notify_all()
        self._write_report()
        return number

    def _record_pc_restart_packet(self, payload, *, direction, peer):
        """Separate private first-N window; it never accepts or acknowledges a packet."""
        from dfserver.transport.native.legacy_ds_wire_codec import decode_observed_application
        with self._lock:
            window = self._pc_restart_capture
            if (window is None or self._stop.is_set() or
                    len(self._pc_restart_records) >= window['packet_limit'] or
                    time.perf_counter() - window['started_at'] >= window['duration_seconds']):
                return
            connection = self._handshake.packet_ack_probe
            ticket, generation = window['ticket'], window['generation']
            current_peer = self._handshake.current_peer_for_generation(generation, ticket)
            state = connection.control_peers.get(current_peer)
            if (peer != current_peer or state is None or state.client_closed or
                    state.ticket is not ticket or not self._admissions.is_active(ticket) or
                    not state.pc_restart_requested or state.pc_restart_actor_guid != window['actor_guid'] or
                    state.pc_restart_channel != window['channel']):
                return
            try:
                # Received datagrams carry the observed 8-byte outer header;
                # both send exits already supply the encoded application body.
                body = payload if direction == 'sent' else payload[8:]
                packet = decode_observed_application(body,
                    max_packet_bytes=connection.max_packet_bytes,
                    received_by_server=direction == 'received')
            except (ValueError, TypeError):
                self._pc_restart_capture_skips['application_framing'] += 1
                return
            # A raw datagram containing another channel could include a Login
            # URL or unrelated application material. Keep the exact private PC
            # body only when this entire datagram lies within the declared scope.
            if any(b.channel_index != window['channel'] for b in packet.bunches):
                self._pc_restart_capture_skips['outside_pc_channel'] += 1
                return
            number = len(self._pc_restart_records) + 1
            name = f'pc-restart-packets/{number:03d}-udp.bin'
            record = {
                'number': number, 'transport': 'udp', 'bytes': len(payload), 'direction': direction,
                'sha256': hashlib.sha256(payload).hexdigest(),
                'captured_at_utc': datetime.now(timezone.utc).isoformat(),
                'elapsed_seconds': round(time.perf_counter() - self._started_at, 6),
                'private_packet_file': name, 'persistence': 'pending',
                'ack_only': not packet.bunches,
                'pc_bunches': [{'reliable': b.reliable, 'sequence': b.channel_sequence,
                    'payload_bits': b.payload_bits, 'partial': b.partial,
                    'partial_initial': b.partial_initial, 'partial_final': b.partial_final}
                    for b in packet.bunches],
            }
            with self._persistence_condition:
                if self._stop.is_set() or self._persistence_stop:
                    return
                self._pc_restart_records.append(record)
                self._persistence_queue.append((number, name, payload, record))
                self._persistence_condition.notify_all()
        self._write_report()

    def _accept_tcp(self):
        self._io_context.network_worker = True
        while not self._stop.is_set():
            try:
                connection, _ = self._tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # A server-first connection can carry no client payload at all.
            # Record the accept separately instead of treating an empty packet
            # list as proof that no TCP connection occurred.
            with self._lock:
                self._tcp_accepted += 1
                if len(self._tcp_accept_samples) < self.max_packets:
                    self._tcp_accept_samples.append({
                        'number': self._tcp_accepted,
                        'accepted_at_utc': datetime.now(timezone.utc).isoformat(),
                    })
            self._write_report()
            with connection:
                connection.settimeout(.5)
                try:
                    self._record('tcp', connection.recv(self.max_bytes))
                except (OSError, socket.timeout):
                    pass

    def _actual_application_send_owner_locked(self, peer):
        if self._handshake is None:
            return None
        self._handshake._expire(time.perf_counter() - self._started_at)
        connection = self._handshake.packet_ack_probe
        if not isinstance(connection, LegacyDSControlConnection):
            return None
        generation = self._handshake.pending.get(peer)
        state, transport = connection.control_peers.get(peer), connection.peers.get(peer)
        if (generation is None or not generation.echoed or generation.verified_at is None or
                state is None or transport is None or
                not connection._current_joined_receipt_owner(peer, state, transport) or
                self._handshake.current_peer_for_generation(generation, state.ticket) != peer):
            return None
        return generation, state.ticket, transport

    def _note_actual_application_send_locked(self, peer, payload, owner):
        current = self._actual_application_send_owner_locked(peer)
        if (type(owner) is not tuple or len(owner) != 3 or current is None or
                any(before is not after for before, after in zip(owner, current))):
            return False
        generation, ticket, transport = current
        return self._handshake.packet_ack_probe._note_actual_application_send(peer, payload,
            generation=generation, ticket=ticket, transport=transport,
            sent_at=time.perf_counter() - self._started_at)

    def _receive_udp(self):
        self._io_context.network_worker = True
        with self._lock:
            self._udp_receive_state = 'running'
        try:
            while not self._stop.is_set():
                try:
                    payload, peer = self._udp.recvfrom(self.max_bytes)
                except socket.timeout:
                    self._send_control_retries()
                    continue
                except OSError as error:
                    if self._stop.is_set():
                        break
                    code = getattr(error, 'winerror', None) or error.errno
                    with self._lock:
                        self._udp_receive_errors[code if type(code) is int else 'unknown'] += 1
                    # On a Windows UDP socket, 10054 can report an earlier
                    # ICMP Port Unreachable from a departed peer. It must not
                    # terminate the shared receiver for subsequent clients.
                    if code == 10054:
                        self._write_report()
                        self._send_control_retries()
                        continue
                    with self._lock:
                        self._udp_receive_state = 'failed'
                        self._udp_receive_failure = {'error_type': type(error).__name__,
                            'error_code': code if type(code) is int else None}
                    break
                profiler = self._receive_profiler()
                if profiler is not None:
                    profiler.enable()
                    began = time.perf_counter()
                try:
                    with self._source_check_cycle(phase='receive'):
                        self._handle_udp_datagram(payload, peer)
                finally:
                    if profiler is not None:
                        profiler.disable()
                        self._note_receive_profile(time.perf_counter() - began)
        except Exception as error:
            # No exception messages or packet contents enter the public report.
            with self._lock:
                self._udp_receive_state = 'failed'
                code = getattr(error, 'winerror', None) or getattr(error, 'errno', None)
                self._udp_receive_failure = {'error_type': type(error).__name__,
                    'error_code': code if type(code) is int else None}
        finally:
            with self._lock:
                if self._udp_receive_state != 'failed':
                    self._udp_receive_state = 'stopped'
            self._write_report()

    def _receive_profiler(self):
        """Diagnostic only: windowed cProfile of UDP receive while a marker file exists.

        The elevated trial helper does not inherit the caller's environment, so
        the switch is the private file work/native-client-tests/PROFILE_RECEIVE.
        Each 30 s window is saved separately so join setup and steady play are
        not mixed; every receive slower than 200 ms is listed with its window.
        """
        if getattr(self, '_receive_profile', None) is None:
            if not (self.capture_dir.parent.parent / 'PROFILE_RECEIVE').exists():
                return None
            import cProfile
            self._receive_profile = cProfile.Profile()
            self._receive_profile_count = 0
            self._receive_profile_window = 0
            self._receive_profile_started = time.perf_counter()
            self._receive_profile_slow = []
        return self._receive_profile

    def _note_receive_profile(self, duration):
        self._receive_profile_count += 1
        elapsed = time.perf_counter() - self._started_at
        if duration >= 0.2 and len(self._receive_profile_slow) < 400:
            self._receive_profile_slow.append((round(elapsed, 2), self._receive_profile_window,
                                               round(duration, 3)))
        if time.perf_counter() - self._receive_profile_started >= 30:
            self._dump_receive_profile()
            import cProfile
            self._receive_profile = cProfile.Profile()
            self._receive_profile_count = 0
            self._receive_profile_window += 1
            self._receive_profile_started = time.perf_counter()

    def _dump_receive_profile(self):
        import io
        import pstats
        stream = io.StringIO()
        stats = pstats.Stats(self._receive_profile, stream=stream)
        total = sum(row[3] for row in stats.stats.values()) if stats.stats else 0.0
        stats.sort_stats('cumulative').print_stats(40)
        stats.sort_stats('tottime').print_stats(25)
        folder = self.capture_dir / 'receive-profile'
        folder.mkdir(exist_ok=True)
        (folder / f'window-{self._receive_profile_window:03d}.txt').write_text(
            f'window={self._receive_profile_window} datagrams={self._receive_profile_count} '
            f'elapsed={round(time.perf_counter() - self._started_at, 1)}\n' + stream.getvalue(),
            encoding='utf-8')
        (folder / 'slow-receives.json').write_text(json.dumps(self._receive_profile_slow), encoding='utf-8')

    def _source_check_cycle(self, *, phase='timer'):
        # Keep the owned callable's code in this module for RuntimeSourceSeal.
        return contextmanager(self._source_check_cycle_generator)(phase=phase)

    def _source_check_cycle_generator(self, *, phase='timer'):
        # The tiny owner snapshot is locked; all file IO occurs after release.
        # A nested retry tick shares only this thread's current receive cycle.
        if getattr(self._io_context, 'source_proof_active', False):
            yield
            return
        if phase not in ('receive', 'timer'):
            raise ValueError('One bounded network source-cycle phase is required')
        from dfserver.replication.legacy_ds_late_player_state_human_appearance import source_proof_cycle
        started = time.perf_counter()
        try:
            with self._lock:
                profiles = [row[2] for row in self._early_player_state_human_appearance_profiles.values()]
                connection = self._handshake.packet_ack_probe if self._handshake is not None else None
                if isinstance(connection, LegacyDSControlConnection):
                    profiles.extend(state.late_player_state_human_appearance_profile
                        for state in connection.control_peers.values()
                        if state.late_player_state_human_appearance_profile is not None)
                profiles = tuple({id(profile): profile for profile in profiles}.values())
            with source_proof_cycle(profiles):
                self._io_context.source_proof_active = True
                try:
                    yield
                finally:
                    self._io_context.source_proof_active = False
        finally:
            duration = max(0.0, time.perf_counter() - started)
            with self._lock:
                metrics = self._source_cycle_processing[phase]
                metrics['count'] += 1
                metrics['total_seconds'] += duration
                metrics['max_seconds'] = max(metrics['max_seconds'], duration)

    def _handle_udp_datagram(self, payload, peer):
        record_number = self._record('udp', payload, peer=peer)
        sent_response = None
        if self._handshake:
            with self._lock:
                diagnostic_owner = (self._actual_application_send_owner_locked(peer)
                    if self._require_initial_actor_profile else None)
                decision = self._handshake.handle(payload, peer, time.perf_counter() - self._started_at)
                if decision.rebound_from_peer is not None:
                    self._rebind_registered_bootstraps_locked(decision.rebound_from_peer, peer)
                self._record_admitted_receipt_locked(payload, peer, decision.event, diagnostic_owner)
                self._pump_static_box_runtimes_locked()
                if record_number is not None:
                    self._records[record_number - 1]['decision'] = decision.event
                if decision.response:
                    # Reserve, send and journal before another timer/wake can
                    # reserve and transmit a later shared packet sequence.
                    send_owner = self._actual_application_send_owner_locked(peer)
                    try:
                        sent = self._udp.sendto(decision.response, peer)
                    except OSError:
                        if self._stop.is_set():
                            return
                    else:
                        if sent == len(decision.response):
                            self._note_actual_application_send_locked(peer, decision.response, send_owner)
                            if decision.event.startswith('empty_packet_ack'):
                                self._packet_ack_sent += 1
                            elif decision.event.startswith('control_'):
                                self._control_sent += 1
                            else:
                                self._handshake_sent += 1
                            sent_response = decision.response
            if sent_response is not None:
                self._record('udp', sent_response, direction='sent', peer=peer)
            self._write_report()
        self._send_control_retries()

    def _send_control_retries(self):
        if self._handshake is None:
            return
        with self._source_check_cycle():
            self._send_control_retries_in_cycle()

    def _send_control_retries_in_cycle(self):
        if self._handshake is None:
            return
        bridge = getattr(self, '_fashion_async_bridge', None)
        if bridge is not None:
            bridge.pump_outside_lock()
        sent_records = []
        with self._lock:
            now = time.perf_counter() - self._started_at
            self._handshake._expire(now)
            self._queue_registered_bootstraps_locked()
            self._pump_static_box_runtimes_locked()
            responses = self._handshake.poll(now)
            connection = self._handshake.packet_ack_probe
            response_owners = {peer: (self._handshake.pending.get(peer),
                getattr(connection.control_peers.get(peer), 'ticket', None), connection.peers.get(peer))
                for peer, _, _ in responses}
            for peer, event, payload in responses:
                # Recheck and send under the same lock as incoming Control closes.
                # A batch encoded before shutdown must not leak out afterwards.
                generation, ticket, original_transport = response_owners[peer]
                self._handshake._expire(time.perf_counter() - self._started_at)
                # The packet may have been encoded before a verified source-port
                # move. Preserve its sequence and route only to that same live
                # generation/ticket; never look up an owner by address alone.
                current_peer = self._handshake.current_peer_for_generation(generation, ticket)
                state = connection.control_peers.get(current_peer)
                actor = event.startswith(('actor_open_', 'actor_content_', 'game_state_',
                                          'pc_restart_', 'pc_rotation_', 'pc_hud_', 'pc_view_target_'))
                keepalive = event == 'transport_keepalive_send_prepared'
                if (current_peer is None or state is None or
                        getattr(state, 'client_closed', False) or
                        connection.peers.get(current_peer) is not original_transport or
                        getattr(state, 'ticket', None) is not ticket or
                        ((actor or keepalive) and (self._admissions is None or
                                    not self._admissions.is_active(ticket)))):
                    if actor:
                        self._bootstrap_events['stale_actor_datagrams_discarded'] += 1
                    else:
                        connection.control_events['stale_control_datagrams_discarded'] += 1
                    continue
                if event.startswith('actor_content_player_state_human_appearance_diagnostic_'):
                    try:
                        if not connection._late_player_state_human_appearance_ready(state, current_peer):
                            continue
                    except (ValueError, OSError, KeyError):
                        self._bootstrap_events['stale_actor_datagrams_discarded'] += 1
                        continue
                if actor and state.early_player_state_human_appearance is not None:
                    try:
                        connection._early_player_state_human_appearance_current(state, current_peer)
                        if (event.startswith('actor_content_') and
                                not event.startswith('actor_content_early_player_state_human_appearance_') and
                                not connection._actual_actor_delivery(state.actor_contents[
                                    state.early_player_state_human_appearance.channel])):
                            continue
                    except (ValueError, OSError, KeyError):
                        self._bootstrap_events['stale_actor_datagrams_discarded'] += 1
                        continue
                try:
                    send_owner = self._actual_application_send_owner_locked(current_peer)
                    if (actor or keepalive) and send_owner is None:
                        continue
                    if event == 'actor_content_fashion_subobject_send_prepared' and not connection._fashion_before_socket(
                            current_peer, payload):
                        continue
                    if event.startswith('actor_content_inventory_') and not connection._inventory_refresh_before_socket(
                            current_peer, payload):
                        continue
                    if event.startswith(('actor_content_world_box_', 'actor_content_world_move_result_')) and not connection._world_delivery_before_socket(
                            current_peer, payload):
                        continue
                    if event.startswith('actor_content_owner_switch_') and not connection._owner_switch_before_socket(
                            current_peer, payload):
                        continue
                    if event == 'actor_content_fashion_async_send_prepared' and (
                            bridge is None or not bridge.before_socket_locked(current_peer, payload)):
                        self._bootstrap_events['fashion_async_socket_recheck_refused'] += 1
                        continue
                    sent = self._udp.sendto(payload, current_peer)
                except OSError:
                    if event == 'actor_content_fashion_async_send_prepared' and bridge is not None:
                        bridge.finish_socket_locked(current_peer, payload, 0)
                    continue
                if sent == len(payload):
                    self._note_actual_application_send_locked(current_peer, payload, send_owner)
                if event == 'actor_content_fashion_async_send_prepared' and bridge is not None:
                    bridge.finish_socket_locked(current_peer, payload, sent)
                    self._bootstrap_events['fashion_async_socket_full_send' if sent == len(payload)
                        else 'fashion_async_socket_short_send'] += 1
                if sent == len(payload):
                    if actor:
                        if event.startswith(('actor_content_', 'game_state_', 'pc_restart_',
                                             'pc_rotation_', 'pc_hud_', 'pc_view_target_')):
                            self._actor_content_sent += 1
                            if event.startswith('actor_content_player_state_human_appearance_diagnostic_'):
                                self._player_state_human_appearance_sent += 1
                            if event.startswith('actor_content_early_player_state_human_appearance_'):
                                self._early_player_state_human_appearance_sent += 1
                            if event.startswith('pc_restart_'):
                                self._pc_restart_sent += 1
                            elif event.startswith('pc_view_target_'):
                                self._pc_view_target_sent += 1
                            elif event.startswith('pc_rotation_'):
                                self._pc_rotation_sent += 1
                            elif event.startswith('pc_hud_'):
                                self._pc_hud_sent += 1
                        else:
                            self._actor_open_sent += 1
                    else:
                        self._control_sent += 1
                        if keepalive:
                            self._transport_keepalive_sent += 1
                if sent == len(payload):
                    sent_records.append((payload, current_peer))
        for payload, current_peer in sent_records:
            self._record('udp', payload, direction='sent', peer=current_peer)
        if bridge is not None:
            bridge.pump_outside_lock()
        if responses:
            self._write_report()
