"""Bounded loopback transport probe for the game's separate DS connection.

This is deliberately not a game server.  It records the first client packets
after a local match handoff so that a server implementation can be based on
observed traffic rather than an assumed Unreal transport. Explicitly enabling
handshake_probe adds a bounded plaintext challenge/ACK experiment. Native
acceptance, transport framing and gameplay still require separate verification.
"""

from collections import Counter, deque
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import threading
import time

from .legacy_ds_handshake_probe import LegacyDSHandshakeProbe
from .legacy_ds_control_connection import LegacyDSControlConnection
from .legacy_ds_match_admission import LocalMatchAdmissions


class GameServerProbe:
    def __init__(self, capture_dir, *, port=0, max_packets=16, max_bytes=65535,
                 handshake_probe=False, packet_ack_probe=False,
                 control_probe=False, expected_net_version=None, control_max_packet_bytes=1024,
                 control_welcome_maps=None):
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
        self._welcome_map_ids = frozenset(control_welcome_maps or {})
        self._handshake = LegacyDSHandshakeProbe(packet_ack_probe=packet_ack_probe,
            control_probe=control_probe, expected_net_version=expected_net_version,
            control_max_packet_bytes=control_max_packet_bytes,
            control_admissions=self._admissions, control_welcome_maps=control_welcome_maps,
            verified_session_ttl=600 if control_welcome_maps is not None else 120) if handshake_probe else None
        self._started_at = time.monotonic()
        self._handshake_sent = 0
        self._packet_ack_sent = 0
        self._control_sent = 0
        self._actor_open_sent = 0
        self._registered_bootstraps = {}
        self._initial_actor_profiles = {}
        self._bootstrap_events = Counter()
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

    @property
    def records(self):
        with self._lock:
            return [record.copy() for record in self._records]

    @property
    def actor_transport_progress(self):
        """Current whole-ticket delivery sets; transport ACKs never prove a spawn."""
        with self._lock:
            if self._handshake is not None:
                self._handshake._expire(time.monotonic() - self._started_at)
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
                    # Match this registration's complete channel/Actor set,
                    # rather than adding ACKs across peers or generations.
                    fields = registration['actor_fields']
                    if fields and all(
                            (delivery := state.actor_opens.get(item['channel_index'])) is not None and
                            delivery.actor_guid == item['actor_guid'] and delivery.delivered
                            for item in fields):
                        fully_delivered_sets += 1
            return {'datagrams_sent': self._actor_open_sent,
                    'delivery_acks': acknowledgments,
                    'fully_delivered_sets': fully_delivered_sets,
                    'native_spawn_verified': False}

    @property
    def listening(self):
        return (self._udp_receive_thread is not None and self._udp_receive_thread.is_alive()
                and self._udp_receive_state in ('starting', 'running') and not self._stop.is_set())

    @property
    def match_admission_enabled(self):
        return self._admissions is not None

    def issue_match_admission(self, *, player_id, room_id, map_id, match_mode_id,
                              selected_hero_id=None):
        if self._admissions is None or not self.listening or map_id not in self._welcome_map_ids:
            raise ValueError('No active evidenced map admission on this local DS')
        ticket = self._admissions.issue(player_id, room_id, map_id, match_mode_id, selected_hero_id)
        with self._lock:
            profile = self._initial_actor_profiles.get(map_id)
        if profile:
            self.register_initial_actor_manifests(ticket, profile['manifests'],
                resolver=profile['resolver'])
        return ticket

    def set_initial_actor_manifests(self, map_id, manifests, *, resolver=None):
        """Configure observed templates for future tickets of one local map.

        This owner-side operation has no client-facing endpoint and no default
        templates. An optional internal producer resolves detached fields once
        after the ticket joins. Preflight is not native object resolution.
        """
        from .legacy_ds_actor_manifest import preflight_actor_manifest

        if (type(map_id) is not int or map_id not in self._welcome_map_ids or
                type(manifests) is not tuple or not 1 <= len(manifests) <= 16 or
                resolver is not None and not callable(resolver)):
            raise ValueError('An evidenced local map and bounded manifest tuple are required')
        with self._lock:
            connection = self._handshake.packet_ack_probe if self._handshake else None
            if not self.listening or not isinstance(connection, LegacyDSControlConnection):
                raise ValueError('An active native local connection is required for the Actor profile')
            staged = tuple(preflight_actor_manifest(manifest, channel_sequence=1023,
                max_packet_bytes=connection.max_packet_bytes) for manifest in manifests)
            self._validate_actor_field_set(tuple(item.actor_fields for item in staged))
            self._initial_actor_profiles[map_id] = {'manifests': manifests, 'resolver': resolver}
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
            self._handshake._expire(time.monotonic() - self._started_at)
            connection = self._handshake.packet_ack_probe
            if not isinstance(connection, LegacyDSControlConnection):
                raise ValueError('Actor transport requires the local ticket connection')
            peers = [peer for peer, state in connection.control_peers.items()
                     if state.client_join_observed and not state.client_closed and state.ticket is not None and
                     state.ticket.player_id == player_id and state.ticket.room_id == room_id]
            if len(peers) != 1:
                raise ValueError('No unique joined peer for the local player and room')
            connection.queue_actor_open(peers[0], **actor_fields)

    def register_initial_actor_manifests(self, ticket, manifests, *, resolver=None):
        """Register explicit templates for this exact local ticket before Join.

        The owner-side producer supplies observed object paths; this entry never
        guesses them or accepts a client-supplied Actor/property payload. A set is
        sent only after the matching admission has joined the local connection.
        """
        from .legacy_ds_actor_manifest import preflight_actor_manifest

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
            self._registered_bootstraps[ticket.cookie] = {
                'ticket': ticket, 'actor_fields': prepared, 'status': 'waiting_for_join',
                'peer': None, 'generation': None, 'resolver': resolver,
            }
            self._bootstrap_events['registered_sets'] += 1
        self._write_report()

    @staticmethod
    def _validate_actor_field_set(prepared):
        """Validate the whole detached export graph before storing any ticket."""
        channels = [fields['channel_index'] for fields in prepared]
        actors = [fields['actor_guid'] for fields in prepared]
        if len(set(channels)) != len(channels) or len(set(actors)) != len(actors):
            raise ValueError('Initial Actors require distinct channels and dynamic GUIDs')
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
        from .legacy_ds_actor_bunch import build_actor_bunch

        resolver = registration['resolver']
        if resolver is None:
            return registration['actor_fields']
        resolved = resolver(ticket, deepcopy(registration['actor_fields']))
        if (type(resolved) is not tuple or not 1 <= len(resolved) <= 16 or
                any(type(fields) is not dict for fields in resolved)):
            raise ValueError('The bootstrap resolver requires a bounded tuple of Actor dictionaries')
        for fields in resolved:
            try:
                build_actor_bunch(channel_sequence=state.initial_actor_sequence,
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
                del self._registered_bootstraps[cookie]
            elif (registration['status'] in ('waiting_for_join', 'queued') and
                    id(registration['ticket']) in closed_tickets):
                registration['status'] = 'client_closed'
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
            try:
                resolved = self._resolved_actor_field_set(ticket, registration, connection, state)
                if not self._admissions.is_active(ticket):
                    raise ValueError('The bootstrap ticket expired during resolution')
                connection.queue_actor_opens(peer, resolved)
            except ValueError:
                registration['status'] = 'rejected'
                self._bootstrap_events['actor_set_precondition_rejected'] += 1
                continue
            registration.update(actor_fields=resolved, status='queued', peer=peer, generation=generation)
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
                registration['peer'] = new_peer
                self._bootstrap_events['authenticated_peer_rebinds'] += 1

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
        self._tcp.close()
        self._udp.close()
        for thread in self._threads:
            thread.join(timeout=3)
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
                'queue_limit': self.max_packets,
                'pending_records': sum(r.get('persistence') == 'pending' for r in self._records),
                'failed_records': sum(r.get('persistence') == 'failed' for r in self._records),
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
                number, name, payload = item
                try:
                    written = (self.capture_dir / name).write_bytes(payload)
                    if written != len(payload):
                        raise OSError('Incomplete bounded packet write')
                except Exception as error:
                    self._persistence_error('packet', error)
                    status = 'failed'
                else:
                    status = 'written'
                with self._lock:
                    self._records[number - 1]['persistence'] = status
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
                report = {'kind': 'local_game_server_transport_probe',
                          'address': '127.0.0.1', 'port': self.port,
                          'listening': self.listening,
                          'udp_receive_state': self._udp_receive_state,
                          'udp_receive_thread_alive': (self._udp_receive_thread is not None and
                                                       self._udp_receive_thread.is_alive()),
                          'udp_receive_errors': dict(self._udp_receive_errors),
                          'udp_receive_failure': (self._udp_receive_failure.copy()
                              if self._udp_receive_failure is not None else None),
                          'gameplay_server_implemented': False,
                          'packet_limit': self.max_packets,
                          'tcp_connections_accepted': self._tcp_accepted,
                          'tcp_accept_samples': list(self._tcp_accept_samples),
                          'handshake_probe': (self._handshake.summary() if self._handshake else {'enabled': False}),
                          'handshake_datagrams_sent': self._handshake_sent,
                          'empty_packet_ack_datagrams_sent': self._packet_ack_sent,
                          'native_control_datagrams_sent': self._control_sent,
                          'initial_actor_open_datagrams_sent': self._actor_open_sent,
                          'initial_actor_bootstrap': {
                              'configured_map_profiles': len(self._initial_actor_profiles),
                              'registered_sets': len(self._registered_bootstraps),
                              'waiting_for_join': sum(item['status'] == 'waiting_for_join'
                                  for item in self._registered_bootstraps.values()),
                              'events': dict(self._bootstrap_events),
                              'native_spawn_verified': False,
                          },
                          'packet_persistence': self._persistence_status_locked(),
                          # A published path always refers to a fully written raw file.
                          'records': [record.copy() for record in self._records
                                      if record.get('persistence') == 'written']}
            temporary = self.capture_dir / 'report.json.tmp'
            temporary.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
            temporary.replace(self.capture_dir / 'report.json')

    def _record(self, transport, payload, *, direction='received', peer=None):
        if not payload:
            return
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
                'elapsed_seconds': round(time.monotonic() - self._started_at, 6),
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
                self._persistence_queue.append((number, name, payload))
                self._persistence_condition.notify_all()
        self._write_report()
        return number

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
                record_number = self._record('udp', payload, peer=peer)
                if self._handshake:
                    with self._lock:
                        decision = self._handshake.handle(payload, peer, time.monotonic() - self._started_at)
                        if decision.rebound_from_peer is not None:
                            self._rebind_registered_bootstraps_locked(decision.rebound_from_peer, peer)
                        if record_number is not None:
                            self._records[record_number - 1]['decision'] = decision.event
                    if decision.response:
                        try:
                            sent = self._udp.sendto(decision.response, peer)
                        except OSError:
                            if self._stop.is_set():
                                break
                        else:
                            if sent == len(decision.response):
                                with self._lock:
                                    if decision.event.startswith('empty_packet_ack'):
                                        self._packet_ack_sent += 1
                                    elif decision.event.startswith('control_'):
                                        self._control_sent += 1
                                    else:
                                        self._handshake_sent += 1
                                self._record('udp', decision.response, direction='sent', peer=peer)
                    self._write_report()
                self._send_control_retries()
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

    def _send_control_retries(self):
        if self._handshake is None:
            return
        with self._lock:
            now = time.monotonic() - self._started_at
            self._handshake._expire(now)
            self._queue_registered_bootstraps_locked()
            responses = self._handshake.poll(now)
            connection = self._handshake.packet_ack_probe
            response_owners = {peer: (self._handshake.pending.get(peer),
                getattr(connection.control_peers.get(peer), 'ticket', None))
                for peer, _, _ in responses}
        for peer, event, payload in responses:
            # Recheck and send under the same lock as incoming Control closes.
            # A batch encoded before shutdown must not leak out afterwards.
            with self._lock:
                generation, ticket = response_owners[peer]
                self._handshake._expire(time.monotonic() - self._started_at)
                # The packet may have been encoded before a verified source-port
                # move. Preserve its sequence and route only to that same live
                # generation/ticket; never look up an owner by address alone.
                current_peer = self._handshake.current_peer_for_generation(generation, ticket)
                state = connection.control_peers.get(current_peer)
                actor = event.startswith('actor_open_')
                if (current_peer is None or state is None or
                        getattr(state, 'client_closed', False) or
                        getattr(state, 'ticket', None) is not ticket or
                        (actor and (self._admissions is None or
                                    not self._admissions.is_active(ticket)))):
                    if actor:
                        self._bootstrap_events['stale_actor_datagrams_discarded'] += 1
                    else:
                        connection.control_events['stale_control_datagrams_discarded'] += 1
                    continue
                try:
                    sent = self._udp.sendto(payload, current_peer)
                except OSError:
                    continue
                if sent == len(payload):
                    if actor:
                        self._actor_open_sent += 1
                    else:
                        self._control_sent += 1
            if sent == len(payload):
                self._record('udp', payload, direction='sent', peer=current_peer)
        if responses:
            self._write_report()
