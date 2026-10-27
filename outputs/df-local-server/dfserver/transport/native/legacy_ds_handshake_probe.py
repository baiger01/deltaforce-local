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

from dfserver.transport.native.unreal_handshake_payload import LegacyHandshakePayload, decode_payload, encode_payload
from dfserver.transport.native.legacy_ds_packet_ack_probe import LegacyDSPacketAckProbe
from dfserver.transport.native.legacy_ds_control_probe import LegacyDSControlProbe
from dfserver.transport.native.legacy_ds_control_connection import ControlConnection, LegacyDSControlConnection, _AdmittedActorReceiptLease, _QualifiedKnownDeliveryReceipt


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
                 verified_session_ttl=120, verified_idle_ttl=60, max_verified_session_ttl=600,
                 control_probe=False, expected_net_version=None, control_max_packet_bytes=1024,
                 control_admissions=None, control_welcome_maps=None,
                 max_restart_candidates=16, max_retired_peers=256, transport_keepalive=False,
                 qualified_receipt_forward_gaps=False):
        if (type(qualified_receipt_forward_gaps) is not bool or qualified_receipt_forward_gaps and
                (not control_probe or control_admissions is None or control_welcome_maps is None)):
            raise ValueError('Qualified receipt forward gaps require explicit local control admission')
        if (type(transport_keepalive) is not bool or transport_keepalive and
                (not control_probe or control_admissions is None or control_welcome_maps is None)):
            raise ValueError('Transport keepalive requires explicit local control admission')
        if control_probe and not packet_ack_probe:
            raise ValueError('Native control step requires the packet transport probe')
        if ((control_admissions is None) != (control_welcome_maps is None) or
                (control_admissions is not None and not control_probe)):
            raise ValueError('Local admission and evidenced map entries require native control')
        if not 1 <= ttl <= 60 or not 1 <= max_peers <= 16 or not 1 <= max_replies <= 16:
            raise ValueError('Invalid bounded handshake probe configuration')
        if (type(max_verified_session_ttl) is not int or not 600 <= max_verified_session_ttl <= 3600 or
                max_verified_session_ttl > 600 and control_admissions is None):
            raise ValueError('Long verified sessions require explicit local match admission')
        for value, maximum in ((verified_session_ttl, max_verified_session_ttl), (verified_idle_ttl, 600)):
            if (isinstance(value, bool) or not isinstance(value, (int, float)) or
                    not math.isfinite(value) or not 1 <= value <= maximum):
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
        self.qualified_delivery_idle_refreshes = 0
        self.verified_expiry_counts = {'idle': 0, 'absolute': 0}
        self.last_verified_expiry = None
        self.packet_ack_probe = (LegacyDSControlConnection(
                                    admissions=control_admissions, welcome_maps=control_welcome_maps,
                                    expected_net_version=expected_net_version,
                                    max_packet_bytes=control_max_packet_bytes,
                                    transport_keepalive=transport_keepalive,
                                    qualified_receipt_forward_gaps=qualified_receipt_forward_gaps)
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
                if challenge.verified_at is not None:
                    reason = ('absolute' if now - challenge.verified_at >= self.verified_session_ttl else 'idle')
                    self.verified_expiry_counts[reason] = min(self.verified_expiry_counts[reason] + 1, 0x7fffffff)
                    self.last_verified_expiry = {'elapsed_seconds': now, 'reason': reason,
                        'last_valid_activity_age_seconds': now - challenge.last_valid_activity_at}
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
            connection = self.packet_ack_probe
            admitted = isinstance(connection, LegacyDSControlConnection)
            prior_challenge = self.pending.get(peer)
            prior_transport = connection.peers.get(peer) if admitted else None
            prior_state = connection.control_peers.get(peer) if admitted else None
            prior_ticket = prior_state.ticket if prior_state is not None else None
            prior_receipt = getattr(connection, '_qualified_known_delivery_receipt', None)
            event, response = (self.packet_ack_probe.handle(datagram, peer, now,
                                                           verified_generation=prior_challenge)
                               if isinstance(self.packet_ack_probe, LegacyDSControlConnection)
                               else self.packet_ack_probe.handle(datagram, peer))
            # Only exact, fully qualified receive outcomes extend idle time.
            # PC '*_packet_consumed' requires every RPC/receipt to pass; mixed
            # legacy outcomes can still contain unknown/refused bodies. The
            # explicit admitted transport receipt is qualified separately below.
            # A fully decoded Ping remains activity when its reply is rate gated.
            consumed = event in ('control_ack_only_consumed', 'control_reliable_retry_consumed',
                'control_login_welcome_prepared', 'control_netspeed_ack_prepared',
                'control_join_ack_prepared', 'pc_startup_packet_consumed',
                'pc_possession_ack_packet_consumed', 'pc_verify_view_target_packet_consumed',
                'pc_ping_rpc_reply_prepared', 'pc_ping_rpc_consumed_without_reply')
            challenge = self.pending.get(peer)
            receipt = getattr(connection, '_qualified_known_delivery_receipt', None)
            current = connection.control_peers.get(peer) if admitted else None
            lease = getattr(current, 'admitted_actor_receipt_lease', None)
            admitted_actor_receipt = (admitted and
                event == 'admitted_actor_reliable_packet_received' and
                challenge is prior_challenge and prior_challenge is not None and
                prior_ticket is not None and prior_transport is not None and current is not None and
                current.ticket is prior_ticket and connection.peers.get(peer) is prior_transport and
                type(lease) is _AdmittedActorReceiptLease and lease.peer == peer and
                lease.ticket is prior_ticket and lease.transport is prior_transport and
                lease.generation is prior_challenge and
                connection._current_joined_receipt_owner(peer, current, prior_transport))
            known_delivery_receipt = (admitted and
                type(receipt) is _QualifiedKnownDeliveryReceipt and receipt is not prior_receipt and
                challenge is prior_challenge and prior_ticket is not None and
                prior_transport is not None and current is not None and
                receipt.peer == peer and receipt.ticket is prior_ticket and
                receipt.generation is prior_challenge and
                current.ticket is receipt.ticket and receipt.transport is prior_transport and
                connection.peers.get(peer) is prior_transport and
                receipt.packet_sequence == prior_transport.in_sequence and receipt.received_at == now and
                connection._current_joined_receipt_owner(peer, current, prior_transport))
            if (challenge is not None and challenge.echoed and challenge.verified_at is not None and
                    (consumed or admitted_actor_receipt or known_delivery_receipt or
                     (response is not None and event.startswith(('empty_packet_ack', 'control_hello'))))):
                challenge.last_valid_activity_at = now
                if known_delivery_receipt:
                    self.qualified_delivery_idle_refreshes = min(
                        self.qualified_delivery_idle_refreshes + 1, 0x7fffffff)
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
                'qualified_delivery_idle_refreshes': self.qualified_delivery_idle_refreshes,
                'verified_expiry_counts': dict(self.verified_expiry_counts),
                'last_verified_expiry': (dict(self.last_verified_expiry)
                                         if self.last_verified_expiry is not None else None),
                'control_channel_implemented': False,
                'native_connection_completed': False, 'gameplay_server_implemented': False,
                'active_peer_count': len(self.pending),
                'peers_with_verified_challenge_echo': sum(state.echoed for state in self.pending.values()),
                'events': dict(self.events)}
