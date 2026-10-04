"""Opt-in plaintext handshake experiment for a loopback DS.

The fixed body is recovered from native code. The eight client-side outer bytes
remain unidentified and are treated as opaque only in this isolated experiment.
The plaintext response envelope has not yet been validated by the native client.
An echoed cookie proves receipt of our challenge, not account authorization,
native connection completion, replication, or a playable game server.
"""
from collections import Counter
from dataclasses import dataclass
import hmac
import math
import secrets
import struct

from .unreal_handshake_payload import LegacyHandshakePayload, decode_payload, encode_payload
from .legacy_ds_packet_ack_probe import LegacyDSPacketAckProbe
from .legacy_ds_control_probe import LegacyDSControlProbe
from .legacy_ds_control_connection import ControlConnection, LegacyDSControlConnection


@dataclass
class PendingChallenge:
    timestamp: float
    cookie: bytes
    issued_at: float
    replies: int = 0
    echoed: bool = False
    verified_at: float | None = None
    last_valid_activity_at: float | None = None


@dataclass
class PendingRestartChallenge:
    """Separate nonce budget; never replaces the original peer generation."""
    timestamp: float
    cookie: bytes
    issued_at: float
    replies: int = 0
    completed: bool = False


@dataclass
class PendingPeerRestartChallenge(PendingRestartChallenge):
    """Unbound nonce until an active old-cookie capability authenticates it."""
    issued_order: int = 0
    generation: PendingChallenge | None = None
    rebound_from_peer: tuple | None = None


@dataclass(frozen=True)
class RetiredPeer:
    generation: PendingChallenge
    absolute_expiry: float


@dataclass(frozen=True)
class HandshakeDecision:
    event: str
    response: bytes | None = None
    rebound_from_peer: tuple | None = None


class LegacyDSHandshakeProbe:
    def __init__(self, *, ttl=30, max_peers=8, max_replies=8, packet_ack_probe=False,
                 verified_session_ttl=120, verified_idle_ttl=60,
                 control_probe=False, expected_net_version=None, control_max_packet_bytes=1024,
                 control_admissions=None, control_welcome_maps=None,
                 max_restart_candidates=16, max_retired_peers=256):
        if control_probe and not packet_ack_probe:
            raise ValueError('Native control step requires the packet transport probe')
        if ((control_admissions is None) != (control_welcome_maps is None) or
                (control_admissions is not None and not control_probe)):
            raise ValueError('Local admission and evidenced map entries require native control')
        if not 1 <= ttl <= 60 or not 1 <= max_peers <= 16 or not 1 <= max_replies <= 16:
            raise ValueError('Invalid bounded handshake probe configuration')
        for value in (verified_session_ttl, verified_idle_ttl):
            if (isinstance(value, bool) or not isinstance(value, (int, float)) or
                    not math.isfinite(value) or not 1 <= value <= 600):
                raise ValueError('Invalid bounded verified-session lifetime')
        if verified_idle_ttl > verified_session_ttl:
            raise ValueError('Verified idle lifetime exceeds the absolute lifetime')
        if (type(max_restart_candidates) is not int or not 1 <= max_restart_candidates <= 32 or
                type(max_retired_peers) is not int or not 1 <= max_retired_peers <= 512):
            raise ValueError('Invalid bounded peer-restart capacity')
        self.ttl, self.max_peers, self.max_replies = ttl, max_peers, max_replies
        self.verified_session_ttl = verified_session_ttl
        self.verified_idle_ttl = verified_idle_ttl
        self.pending = {}
        self.restart_pending = {}
        self.peer_restart_pending = {}
        self.retired_peers = {}
        self.max_restart_candidates, self.max_retired_peers = max_restart_candidates, max_retired_peers
        self._restart_order = 0
        self._migration_order = {}
        self.events = Counter()
        self.packet_ack_probe = (LegacyDSControlConnection(
                                    admissions=control_admissions, welcome_maps=control_welcome_maps,
                                    expected_net_version=expected_net_version,
                                    max_packet_bytes=control_max_packet_bytes)
                                if control_admissions is not None else
                                LegacyDSControlProbe(expected_net_version=expected_net_version,
                                                    max_packet_bytes=control_max_packet_bytes)
                                if control_probe else
                                LegacyDSPacketAckProbe() if packet_ack_probe else None)

    def _decision(self, event, response=None, *, rebound_from_peer=None):
        self.events[event] += 1
        return HandshakeDecision(event, response, rebound_from_peer)

    def _expire(self, now):
        for peer, challenge in list(self.pending.items()):
            expired = (now - challenge.issued_at >= self.ttl if challenge.verified_at is None
                       else (now - challenge.verified_at >= self.verified_session_ttl or
                             now - challenge.last_valid_activity_at >= self.verified_idle_ttl))
            if expired:
                del self.pending[peer]
                self.restart_pending.pop(peer, None)
                self._migration_order.pop(id(challenge), None)
                if self.packet_ack_probe:
                    self.packet_ack_probe.forget_peer(peer)
        for peer, restart in list(self.restart_pending.items()):
            if peer not in self.pending or now - restart.issued_at >= self.ttl:
                del self.restart_pending[peer]
        for peer, restart in list(self.peer_restart_pending.items()):
            if (now - restart.issued_at >= self.ttl or
                    (restart.completed and self.pending.get(peer) is not restart.generation)):
                del self.peer_restart_pending[peer]
        for peer, retired in list(self.retired_peers.items()):
            if now >= retired.absolute_expiry:
                del self.retired_peers[peer]

    def _restart_session(self, peer):
        """Restore only one existing same-peer capability, never account admission."""
        original = self.pending.get(peer)
        if (original is None or not original.echoed or original.verified_at is None or
                not any(original.cookie)):
            return None, 'restart_without_verified_cookie'
        if self.packet_ack_probe is None:
            return None, 'restart_transport_missing'
        if self.packet_ack_probe:
            if peer not in self.packet_ack_probe.peers:
                return None, 'restart_transport_missing'
            if isinstance(self.packet_ack_probe, LegacyDSControlProbe):
                state = self.packet_ack_probe.control_peers.get(peer)
                if state is None:
                    return None, 'restart_control_missing'
                if isinstance(self.packet_ack_probe, LegacyDSControlConnection):
                    if not isinstance(state, ControlConnection):
                        return None, 'restart_control_missing'
                    if state.client_closed:
                        return None, 'restart_client_closed'
                    if state.ticket is not None:
                        try:
                            active = self.packet_ack_probe.admissions.is_active(state.ticket)
                        except Exception:
                            active = False
                        if not active:
                            return None, 'restart_ticket_inactive'
                        if self.packet_ack_probe.ticket_peers.get(state.ticket.cookie) != peer:
                            return None, 'restart_ticket_binding_rejected'
        return original, None

    def _handle_restart(self, message, peer, now):
        # Native writer12bc91a0 appends oldcookie on its restart echo; native
        # Incoming12bb9b40 skips InitializeSequence and cookie replacement on
        # the matching negative ACK. No register/forget/reseed happens here.
        if peer not in self.pending or peer in self.peer_restart_pending:
            return self._handle_peer_restart(message, peer, now)
        original, rejection = self._restart_session(peer)
        if rejection:
            return self._decision(rejection)
        restart = self.restart_pending.get(peer)
        if (message.timestamp == 0 and not any(message.cookie) and
                message.old_cookie is None):
            if restart is None:
                timestamp = struct.unpack('<f', struct.pack('<f', max(0.001, now)))[0]
                restart = PendingRestartChallenge(timestamp, secrets.token_bytes(20), now)
            if restart.replies >= self.max_replies:
                return self._decision('restart_reply_limit_reached')
            body = encode_payload(LegacyHandshakePayload(
                False, False, restart.timestamp, restart.cookie))
            self.restart_pending[peer] = restart
            restart.replies += 1
            # Initials/retries neither authorize nor refresh the original session.
            return self._decision('restart_challenge_reply_prepared', body)
        if message.old_cookie is None or message.timestamp <= 0:
            return self._decision('restart_requires_extended_echo')
        if (restart is None or message.timestamp != restart.timestamp or
                not hmac.compare_digest(message.cookie, restart.cookie) or
                not hmac.compare_digest(message.old_cookie, original.cookie)):
            return self._decision('restart_echo_rejected')
        if restart.replies >= self.max_replies:
            return self._decision('restart_reply_limit_reached')
        body = encode_payload(LegacyHandshakePayload(False, True, -1.0, original.cookie))
        restart.replies += 1
        if restart.completed:
            # A duplicate can repeat the ACK, but cannot refresh activity/expiry.
            return self._decision('restart_echo_retry_ack_prepared', body)
        restart.completed = True
        original.last_valid_activity_at = now
        return self._decision('valid_restart_echo_ack_prepared', body)

    def _admitted_restart_session(self, peer):
        original, rejection = self._restart_session(peer)
        if rejection:
            return None, rejection
        connection = self.packet_ack_probe
        if (not isinstance(connection, LegacyDSControlConnection) or
                connection.control_peers[peer].ticket is None):
            return None, 'restart_admitted_control_required'
        return original, None

    def _handle_peer_restart(self, message, peer, now):
        """Authenticate a new source port, then move the existing generation.

        Native 12bc91a0 supplies a fresh nonce and the old 20-byte cookie. The
        ownership/capacity/retired-port policy below is local, bounded policy;
        it is not a claim that the proprietary driver's whole routing is known.
        """
        restart = self.peer_restart_pending.get(peer)
        initial = (message.timestamp == 0 and not any(message.cookie) and
                   message.old_cookie is None)
        if initial:
            if restart is None:
                # A zero-cookie initial proves nothing about an owner. It may
                # receive a nonce only while an admitted capability exists.
                if peer in self.pending or (self.packet_ack_probe is not None and
                        (peer in self.packet_ack_probe.peers or
                         peer in getattr(self.packet_ack_probe, 'control_peers', {}))):
                    return self._decision('restart_destination_occupied')
                if not any(self._admitted_restart_session(owner)[0] is not None
                           for owner in self.pending):
                    return self._decision('restart_without_verified_cookie')
                if len(self.peer_restart_pending) >= self.max_restart_candidates:
                    return self._decision('restart_candidate_limit_reached')
                timestamp = struct.unpack('<f', struct.pack('<f', max(0.001, now)))[0]
                self._restart_order += 1
                restart = PendingPeerRestartChallenge(timestamp, secrets.token_bytes(20), now,
                                                      issued_order=self._restart_order)
            elif restart.completed:
                original, rejection = self._admitted_restart_session(peer)
                if rejection or original is not restart.generation:
                    return self._decision(rejection or 'restart_generation_changed')
            if restart.replies >= self.max_replies:
                return self._decision('restart_reply_limit_reached')
            body = encode_payload(LegacyHandshakePayload(
                False, False, restart.timestamp, restart.cookie))
            self.peer_restart_pending[peer] = restart
            restart.replies += 1
            return self._decision('restart_peer_challenge_reply_prepared', body)
        if message.old_cookie is None or message.timestamp <= 0:
            return self._decision('restart_requires_extended_echo')
        if (restart is None or message.timestamp != restart.timestamp or
                not hmac.compare_digest(message.cookie, restart.cookie)):
            return self._decision('restart_peer_echo_rejected')
        if restart.replies >= self.max_replies:
            return self._decision('restart_reply_limit_reached')
        if restart.completed:
            original, rejection = self._admitted_restart_session(peer)
            if (rejection or original is not restart.generation or
                    not hmac.compare_digest(message.old_cookie, original.cookie)):
                return self._decision(rejection or 'restart_peer_echo_rejected')
            body = encode_payload(LegacyHandshakePayload(False, True, -1.0, original.cookie))
            restart.replies += 1
            return self._decision('restart_peer_echo_retry_ack_prepared', body,
                                  rebound_from_peer=restart.rebound_from_peer)
        # Include all verified matches before filtering admission: duplicate
        # capabilities are ambiguous even if one owner has become invalid.
        matches = [(owner, original) for owner, original in self.pending.items()
                   if original.echoed and original.verified_at is not None and
                   any(original.cookie) and hmac.compare_digest(message.old_cookie, original.cookie)]
        if len(matches) != 1:
            return self._decision('restart_old_cookie_ambiguous' if matches else
                                  'restart_old_cookie_unverified')
        old_peer, original = matches[0]
        admitted, rejection = self._admitted_restart_session(old_peer)
        if rejection or admitted is not original:
            return self._decision(rejection or 'restart_generation_changed')
        if (old_peer == peer or peer in self.pending or peer in self.packet_ack_probe.peers or
                peer in self.packet_ack_probe.control_peers):
            return self._decision('restart_destination_occupied')
        if restart.issued_order <= self._migration_order.get(id(original), 0):
            return self._decision('restart_candidate_predates_migration')
        if len(self.retired_peers) >= self.max_retired_peers:
            return self._decision('restart_retired_peer_limit_reached')
        body = encode_payload(LegacyHandshakePayload(False, True, -1.0, original.cookie))
        retired = RetiredPeer(original, original.verified_at + self.verified_session_ttl)
        # Every fallible validation/serialization precedes this dictionary-only
        # commit. Caller owns the Probe lock. Do not register/forget/clone/reseed.
        try:
            self.packet_ack_probe.rebind_verified_peer(old_peer, peer)
        except ValueError:
            return self._decision('restart_transport_rebind_rejected')
        self.pending[peer] = self.pending.pop(old_peer)
        self.restart_pending.pop(old_peer, None)
        self.peer_restart_pending.pop(old_peer, None)
        self.retired_peers[old_peer] = retired
        self._restart_order += 1
        self._migration_order[id(original)] = self._restart_order
        restart.completed, restart.generation, restart.rebound_from_peer = True, original, old_peer
        restart.replies += 1
        original.last_valid_activity_at = now
        return self._decision('valid_restart_peer_echo_ack_prepared', body,
                              rebound_from_peer=old_peer)

    def current_peer_for_generation(self, generation, ticket):
        """Resolve one live owner for an already constructed timer response.

        Caller must expire under its lock first. A pre-Login ticket=None keeps
        its original owner but cannot authorize a cross-peer restart.
        """
        if generation is None:
            return None
        owners = [peer for peer, original in self.pending.items() if original is generation]
        if len(owners) != 1:
            return None
        peer = owners[0]
        original, rejection = self._restart_session(peer)
        if rejection or original is not generation:
            return None
        state = getattr(self.packet_ack_probe, 'control_peers', {}).get(peer)
        if isinstance(self.packet_ack_probe, LegacyDSControlConnection):
            if not isinstance(state, ControlConnection) or state.ticket is not ticket:
                return None
        elif ticket is not None:
            return None
        return peer

    def poll(self, now):
        """Send pending reliable Control/Actor data without extending client activity."""
        if (isinstance(now, bool) or not isinstance(now, (int, float)) or
                not math.isfinite(now) or now < 0):
            raise ValueError('A finite monotonic timestamp is required')
        self._expire(now)
        if isinstance(self.packet_ack_probe, LegacyDSControlConnection):
            responses = self.packet_ack_probe.poll(now)
            for _, event, _ in responses:
                self.events[event] += 1
            return responses
        return []

    def handle(self, datagram, peer, now):
        if (not isinstance(peer, tuple) or len(peer) != 2 or peer[0] != '127.0.0.1' or
                type(peer[1]) is not int or not 1 <= peer[1] <= 65535):
            return self._decision('non_loopback_peer_rejected')
        if not isinstance(now, (float, int)) or isinstance(now, bool) or not math.isfinite(now) or now < 0:
            raise ValueError('A finite monotonic timestamp is required')
        self._expire(now)
        if peer in self.retired_peers:
            return self._decision('retired_peer_rejected')
        if self.packet_ack_probe and isinstance(datagram, bytes) and len(datagram) >= 9 and not datagram[8] & 1:
            event, response = (self.packet_ack_probe.handle(datagram, peer, now)
                               if isinstance(self.packet_ack_probe, LegacyDSControlConnection)
                               else self.packet_ack_probe.handle(datagram, peer))
            # Parsed controls and ACK-only packets that were consumed count
            # as activity. Unknown controls and rejects cannot extend it.
            consumed = event in ('control_ack_only_consumed', 'control_reliable_retry_consumed',
                'control_login_welcome_prepared', 'control_netspeed_ack_prepared',
                'control_join_ack_prepared')
            if consumed or (response is not None and event.startswith(('empty_packet_ack', 'control_hello'))):
                self.pending[peer].last_valid_activity_at = now
            return self._decision(event, response)
        if not isinstance(datagram, bytes) or len(datagram) not in (33, 53):
            return self._decision('unhandled_datagram_shape')
        try:
            message = decode_payload(datagram[8:])
        except ValueError:
            return self._decision('fixed_body_rejected')
        if message.third_flag:
            return self._decision('unsupported_flags')
        if message.restart:
            return self._handle_restart(message, peer, now)
        restart = self.restart_pending.get(peer)
        peer_restart = self.peer_restart_pending.get(peer)
        if ((restart is not None and not restart.completed) or
                (peer_restart is not None and not peer_restart.completed)):
            # A delayed ordinary echo cannot bypass the fresh restart challenge.
            return self._decision('restart_requires_extended_echo')
        challenge = self.pending.get(peer)
        if message.timestamp == 0 and not any(message.cookie):
            if challenge is None:
                if len(self.pending) >= self.max_peers:
                    return self._decision('peer_limit_reached')
                # Client code requires a positive float32 challenge time.
                timestamp = struct.unpack('<f', struct.pack('<f', max(0.001, now)))[0]
                challenge = PendingChallenge(timestamp, secrets.token_bytes(20), now)
                self.pending[peer] = challenge
            if challenge.replies >= self.max_replies:
                return self._decision('reply_limit_reached')
            challenge.replies += 1
            body = encode_payload(LegacyHandshakePayload(False, False, challenge.timestamp, challenge.cookie))
            return self._decision('challenge_reply_prepared', body)
        if message.timestamp <= 0 or challenge is None:
            return self._decision('unsolicited_echo_rejected')
        if (message.timestamp != challenge.timestamp or
                not hmac.compare_digest(message.cookie, challenge.cookie)):
            return self._decision('challenge_echo_rejected')
        if challenge.replies >= self.max_replies:
            return self._decision('reply_limit_reached')
        challenge.replies += 1
        challenge.echoed = True
        if challenge.verified_at is None:
            challenge.verified_at = now
            challenge.last_valid_activity_at = now
        if self.packet_ack_probe:
            self.packet_ack_probe.register_verified_echo(peer, challenge.cookie)
        body = encode_payload(LegacyHandshakePayload(False, True, -1.0, challenge.cookie))
        return self._decision('valid_challenge_echo_ack_prepared', body)

    def summary(self):
        return {'enabled': True, 'mode': 'experimental_loopback_plaintext_fixed_body',
                'candidate_client_body_offset': 8, 'server_response_bytes': 25,
                'outer_header_verified': False, 'native_acceptance_verified': False,
                'same_peer_restart_implemented': True,
                'cross_peer_restart_supported': isinstance(self.packet_ack_probe, LegacyDSControlConnection),
                'cross_peer_restart_policy': 'unique_active_ticket_and_old_cookie_preserve_generation',
                'restart_completed_initial_policy': 'idempotent_same_nonce_until_challenge_ttl',
                'active_restart_challenge_count': len(self.restart_pending),
                'active_peer_restart_challenge_count': len(self.peer_restart_pending),
                'retired_peer_count': len(self.retired_peers),
                'peer_restart_candidate_limit': self.max_restart_candidates,
                'retired_peer_limit': self.max_retired_peers,
                'account_authorized_by_cookie_echo': False,
                'packet_ack_probe_enabled': self.packet_ack_probe is not None,
                'native_control_probe': (self.packet_ack_probe.summary()
                    if isinstance(self.packet_ack_probe, LegacyDSControlProbe) else {'enabled': False}),
                'challenge_ttl_seconds': self.ttl,
                'verified_session_ttl_seconds': self.verified_session_ttl,
                'verified_idle_ttl_seconds': self.verified_idle_ttl,
                'control_channel_implemented': False,
                'native_connection_completed': False, 'gameplay_server_implemented': False,
                'active_peer_count': len(self.pending),
                'peers_with_verified_challenge_echo': sum(state.echoed for state in self.pending.values()),
                'events': dict(self.events)}
