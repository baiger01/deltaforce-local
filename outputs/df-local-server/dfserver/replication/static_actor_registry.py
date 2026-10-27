"""Current server static GUID allocations with exact positive export receipts.

An entry proves the server's admitted path namespace and export delivery. It
does not prove a client UObject resolved, a lock permission or a world position.
The caller qualifies each manifest against its source rows before construction.
"""
from dataclasses import dataclass, field, replace
import hashlib
from types import MappingProxyType

from dfserver._paths import PROJECT_ROOT
from dfserver.legacy_ds_control_connection import (ActorOpenDelivery, ControlConnection,
    LegacyDSControlConnection, _ActualActorReceipt, _AdmittedActorReceiptLease)
from dfserver.legacy_ds_static_actor_manifest import StaticActorManifest, preflight_static_actor_manifest
from dfserver.legacy_ds_match_admission import LocalMatchTicket


@dataclass(frozen=True)
class StaticActorRegistration:
    actor_path: str
    class_path: str
    actor_guid: int
    channel_index: int
    path_bindings: tuple
    ticket: object = field(repr=False)
    transport: object = field(repr=False)
    generation: object = field(repr=False)
    export_receipt: _ActualActorReceipt = field(repr=False)
    manifest: StaticActorManifest = field(repr=False)
    native_resolution_observed: bool = field(default=False, init=False)


@dataclass(frozen=True)
class StaticActorRegistryProfile:
    ticket: LocalMatchTicket = field(repr=False)
    manifests: tuple
    source_pins: tuple
    sources_current: object = field(repr=False)
    runtime_factory: object = field(repr=False)

    def __post_init__(self):
        if (type(self.ticket) is not LocalMatchTicket
                or type(self.manifests) is not tuple or not 1 <= len(self.manifests) <= 3
                or any(type(m) is not StaticActorManifest for m in self.manifests)
                or type(self.source_pins) is not tuple or not self.source_pins
                or len(dict(self.source_pins)) != len(self.source_pins)
                or not callable(self.sources_current) or self.sources_current() is not True
                or not callable(self.runtime_factory)):
            raise ValueError('One qualified static Actor source lease and runtime producer are required')

    def create(self, connection, peer):
        self.__post_init__()
        state = connection.control_peers.get(peer)
        if type(state) is not ControlConnection or state.ticket is not self.ticket:
            raise ValueError('The static registry profile belongs to another admission ticket')
        registry = AdmittedStaticActorRegistry(connection, peer, self.manifests,
            source_pins=dict(self.source_pins), sources_current=self.sources_current)
        return self.runtime_factory(registry)


class AdmittedStaticActorRegistry:
    """One bounded, immutable namespace bound to the current admitted lease."""
    def __init__(self, connection, peer, manifests, *, source_pins, sources_current=None):
        if (type(connection) is not LegacyDSControlConnection or type(manifests) is not tuple
                or not 1 <= len(manifests) <= 3 or type(source_pins) is not dict or not source_pins):
            raise ValueError('The actual Control and bounded qualified static manifests are required')
        self.connection, self.peer = connection, peer
        self._pins = MappingProxyType(dict(source_pins))
        self.sources_current = sources_current
        for relative, digest in self._pins.items():
            if (type(relative) is not str or '\\' in relative or relative.startswith('/')
                    or '..' in relative.split('/') or type(digest) is not str or len(digest) != 64
                    or any(c not in '0123456789abcdef' for c in digest)):
                raise ValueError('The static registry requires canonical source paths and exact SHA256')
        state, transport = connection.control_peers.get(peer), connection.peers.get(peer)
        if type(state) is not ControlConnection or type(state.admitted_actor_receipt_lease) is not _AdmittedActorReceiptLease:
            raise ValueError('The exact current admitted Actor receipt lease is required')
        self.ticket, self.transport, self.lease = state.ticket, transport, state.admitted_actor_receipt_lease
        self.generation = connection._local_stage_owner(peer, state, transport)
        self.entries = ()
        self._by_guid = MappingProxyType({})
        self.current()
        entries, paths, channels, namespace = [], set(), set(), {}
        for manifest in manifests:
            if type(manifest) is not StaticActorManifest or self._pins.get(manifest.source_relative_path) != manifest.source_sha256:
                raise ValueError('Each static manifest must name its frozen source receipt')
            opened = state.actor_opens.get(manifest.channel_index)
            if type(opened) is not ActorOpenDelivery:
                raise ValueError('The static Actor has no actual admitted open')
            preflight = preflight_static_actor_manifest(manifest,
                channel_sequence=opened.bunch.channel_sequence, max_packet_bytes=connection.max_packet_bytes)
            if (opened.actor_guid != manifest.actor_guid or opened.bunch != preflight.bunch
                    or dict(opened.open_fields) != dict(preflight.actor_fields)
                    or manifest.actor_path in paths or manifest.channel_index in channels):
                raise ValueError('The static manifest differs from its exact admitted wire open')
            for binding in manifest.path_bindings:
                if binding.guid in namespace and namespace[binding.guid] != binding.full_path:
                    raise ValueError('The admitted static export namespace aliases a GUID')
                namespace[binding.guid] = binding.full_path
            receipts = [receipt for receipt in state.actual_actor_receipts
                if type(receipt) is _ActualActorReceipt and receipt.actor_guid == manifest.actor_guid
                and receipt.bunch == opened.bunch and receipt.ticket is self.ticket
                and receipt.transport is self.transport and receipt.generation is self.generation]
            if len(receipts) != 1:
                raise ValueError('The exact positive full-send export receipt is required')
            entries.append(StaticActorRegistration(manifest.actor_path, manifest.class_path, manifest.actor_guid,
                manifest.channel_index, manifest.path_bindings, self.ticket, self.transport,
                self.generation, receipts[0], manifest))
            paths.add(manifest.actor_path)
            channels.add(manifest.channel_index)
        if len({entry.actor_guid for entry in entries}) != len(entries):
            raise ValueError('The admitted static Actors alias a GUID')
        self.entries = tuple(entries)
        self._by_guid = MappingProxyType({entry.actor_guid: entry for entry in entries})
        self.current()

    def current(self):
        state = self.owner_current()
        self._check_sources()
        return state

    def _check_sources(self):
        if self.sources_current is not None:
            if not callable(self.sources_current) or self.sources_current() is not True:
                raise ValueError('The frozen static registry sources changed')
        else:
            for relative, expected in self._pins.items():
                path = PROJECT_ROOT / relative
                if (not path.resolve().is_relative_to(PROJECT_ROOT.resolve())
                        or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
                    raise ValueError('The frozen static registry sources changed')

    def rebind_authenticated_peer(self, old_peer, new_peer):
        """Follow Control's verified key/lease move without recreating receipts."""
        connection = self.connection
        state, transport = connection.control_peers.get(new_peer), connection.peers.get(new_peer)
        lease = getattr(state, 'admitted_actor_receipt_lease', None)
        if (self.peer != old_peer or old_peer == new_peer
                or old_peer in connection.control_peers or old_peer in connection.peers
                or type(state) is not ControlConnection or state.ticket is not self.ticket
                or connection.ticket_peers.get(self.ticket.cookie) != new_peer
                or transport is not self.transport
                or connection._local_stage_owner(new_peer, state, transport) is not self.generation
                or type(lease) is not _AdmittedActorReceiptLease
                or lease.ticket is not self.ticket or lease.transport is not self.transport
                or lease.generation is not self.generation or self.lease.peer != old_peer
                or lease != replace(self.lease, peer=new_peer)):
            raise ValueError('Only the same authenticated static registry owner may change its peer')
        connection._admitted_actor_receipt_binding(state, state, new_peer, transport, self.generation)
        self._check_sources()
        if any(not any(receipt is entry.export_receipt for receipt in state.actual_actor_receipts)
                for entry in self.entries):
            raise ValueError('The static export receipt identity changed during authenticated peer migration')
        self.peer, self.lease = new_peer, lease

    def owner_current(self):
        """Check live ownership and receipts without source IO on idle ticks."""
        connection, peer = self.connection, self.peer
        state, transport = connection.control_peers.get(peer), connection.peers.get(peer)
        if (type(state) is not ControlConnection or state.ticket is not self.ticket
                or transport is not self.transport or state.admitted_actor_receipt_lease is not self.lease
                or connection._local_stage_owner(peer, state, transport) is not self.generation):
            raise ValueError('The static registry ticket, transport or generation changed')
        connection._admitted_actor_receipt_binding(state, state, peer, transport, self.generation)
        for entry in self.entries:
            if not any(receipt is entry.export_receipt for receipt in state.actual_actor_receipts):
                raise ValueError('The current static export receipt identity changed')
        return state

    def lookup(self, actor_guid):
        self.current()
        if type(actor_guid) is not int or actor_guid not in self._by_guid:
            raise ValueError('The reference is outside this actual admitted static Actor namespace')
        return self._by_guid[actor_guid]
