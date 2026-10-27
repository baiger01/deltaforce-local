"""Finite local dispatch after the owning transport has admitted a native RPC.

The caller owns current transport admission, movement authority, verified live
world membership and actual Actor/export receipts. It supplies ready_box_guids
only for those successful live bindings. Returned projections remain pending
until the caller records every actual reliable ACK. No socket or account I/O.
"""
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import threading

from dfserver.legacy_ds_inventory_items import InventoryItemLocation
import portable_finite_loot as finite
import portable_loot_box_codec as boxes
import portable_loot_box_request as opens
import portable_world_item_move_request as moves
import portable_world_interact_request as interactions
from portable_map_inventory import base_item
from normal_map_archive_values import NativeName


@dataclass(frozen=True)
class OpenDispatchResult:
    request: opens.OpenBoxRequest
    snapshot: finite.LootSnapshot
    projection: boxes.LootBoxProjection


@dataclass(frozen=True)
class MoveDispatchResult:
    request: moves.ItemMoveRequest
    receipt: finite.TransferReceipt
    box_snapshot: finite.LootSnapshot
    inventory_snapshot: finite.LootSnapshot


@dataclass(frozen=True)
class InteractDispatchResult:
    request: interactions.InteractRequest
    snapshot: finite.LootSnapshot
    projection: boxes.LootBoxProjection


def source_pins():
    result = moves.source_pins()
    result.update(opens.source_pins())
    result.update(finite.source_pins())
    result.update(interactions.source_pins())
    path = Path(__file__).resolve()
    result['work/portable_world_loot_dispatch.py'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


class WorldLootDispatcher:
    """One match/player, finite initial contents and exact whole-move retries.

    Whole moves into an explicitly chosen free inventory grid are the supported
    local policy. Splits, swaps, auto placement, equipment lifecycle, keycards,
    search animation progress and native success RPCs require their own handlers.
    """
    def __init__(self, authority, *, recipient_scope, bindings_by_guid,
            player_actor_guid, maximum_distance_cm, interaction_allowed=None):
        source_pins()
        if type(authority) is not finite.FiniteLootAuthority:
            raise ValueError('The actual current finite match authority is required')
        if (type(recipient_scope) is not tuple or len(recipient_scope) != 2 or
                recipient_scope[0] != authority.match_id or type(recipient_scope[1]) is not int or
                not 0 < recipient_scope[1] < 1 << 64):
            raise ValueError('The exact finite match/player namespace is required')
        if (type(player_actor_guid) is not int or not 2 <= player_actor_guid < 1 << 32 or
                type(maximum_distance_cm) not in (int, float) or
                not math.isfinite(maximum_distance_cm) or not 0 < maximum_distance_cm <= 10000):
            raise ValueError('The actual Pawn reference and bounded local distance policy are required')
        if type(bindings_by_guid) is not dict or not 1 <= len(bindings_by_guid) <= 3:
            raise ValueError('A bounded exact source box map is required')
        self._bindings = dict(bindings_by_guid)
        self._original_items = {}
        paths = set()
        for guid, binding in self._bindings.items():
            if type(guid) is not int or not 3 <= guid < 1 << 32 or not guid & 1:
                raise ValueError('An ordinary mapped static box GUID is required')
            boxes.qualify_binding(binding)
            if binding.object_path in paths:
                raise ValueError('The source box map aliases one existing world Actor')
            paths.add(binding.object_path)
            snapshot = authority.box_snapshot(binding.object_path)
            for element in snapshot.items:
                item = base_item(element.item)
                self._original_items[(binding.object_path, item.item_gid)] = (
                    item.location.length, item.location.height, boxes.item_quantity(element.item))
        authority.inventory_snapshot(recipient_scope[1])
        self._authority = authority
        self._recipient = recipient_scope
        self._player_actor_guid = player_actor_guid
        self._maximum_distance = maximum_distance_cm
        if interaction_allowed is not None and not callable(interaction_allowed):
            raise ValueError('The current server interaction authority must be a callback')
        self._interaction_allowed = interaction_allowed
        self._requests = {}
        self._lock = threading.RLock()

    def _context(self, guid, *, ready_box_guids, references_resolved, exports_acknowledged):
        if references_resolved is not True or exports_acknowledged is not True:
            raise ValueError('Current actual type resolution and export ACKs are required')
        if (type(ready_box_guids) is not frozenset or
                not ready_box_guids <= self._bindings.keys() or guid not in ready_box_guids):
            raise ValueError('The exact live-world box Actor has no successful current receipt binding')

    def open_field(self, field, *, player_position, ready_box_guids,
            references_resolved, exports_acknowledged, cursor=None):
        request = opens.decode_field(field, bindings_by_guid=self._bindings,
            references_resolved=references_resolved, exports_acknowledged=exports_acknowledged,
            recipient_scope=self._recipient)
        self._context(request.box_guid, ready_box_guids=ready_box_guids,
            references_resolved=references_resolved, exports_acknowledged=exports_acknowledged)
        with self._lock:
            if (not callable(self._interaction_allowed) or self._interaction_allowed(
                    recipient_scope=self._recipient, binding=request.binding,
                    operator_tag=NativeName('Interactor.CheckCollision.ContainerBox.Open', 0)) is not True):
                raise ValueError('The authoritative current box lock/permission state rejects this UI open')
            snapshot = self._authority.open_box(self._recipient[1], request.binding.object_path,
                player_position=player_position, maximum_distance_cm=self._maximum_distance)
            projection = boxes.project(request.binding, snapshot.spaces, snapshot.items,
                recipient_scope=self._recipient, cursor=cursor)
            return OpenDispatchResult(request, snapshot, projection)

    def move_field(self, field, **context):
        return self.move_request(moves.decode_field(field), **context)

    def interact_field(self, field, *, player_position, ready_box_guids,
            references_resolved, exports_acknowledged, nonfast_replication_confirmed,
            interaction_allowed, cursor=None):
        """Local immediate open policy after the server checks its actual lock state.

        interaction_allowed is a short server callback, never a client flag or
        client context position. Root must supply an actual lock/permission
        authority and keep changes in that state exclusive with this operation.
        """
        request = interactions.decode_field(field, bindings_by_guid=self._bindings,
            nonfast_replication_confirmed=nonfast_replication_confirmed,
            references_resolved=references_resolved, exports_acknowledged=exports_acknowledged)
        self._context(request.target_guid, ready_box_guids=ready_box_guids,
            references_resolved=references_resolved, exports_acknowledged=exports_acknowledged)
        if (request.operator_tag.base_name != 'Interactor.CheckCollision.ContainerBox.Open' or
                not callable(interaction_allowed)):
            raise ValueError('Only an actual server-permitted box-open operator is implemented')
        with self._lock:
            if interaction_allowed(recipient_scope=self._recipient, binding=request.binding,
                    operator_tag=request.operator_tag) is not True:
                raise ValueError('The authoritative current box lock/permission state rejects this operator')
            snapshot = self._authority.open_box(self._recipient[1], request.binding.object_path,
                player_position=player_position, maximum_distance_cm=self._maximum_distance)
            projection = boxes.project(request.binding, snapshot.spaces, snapshot.items,
                recipient_scope=self._recipient, cursor=cursor)
            return InteractDispatchResult(request, snapshot, projection)

    def move_bunch(self, bunch, *, pawn_channel, inventory_manager_guid, **context):
        return self.move_request(moves.decode_bunch(bunch, pawn_channel=pawn_channel,
            inventory_manager_guid=inventory_manager_guid), **context)

    def move_request(self, request, *, player_position, ready_box_guids,
            references_resolved, exports_acknowledged):
        if type(request) is not moves.ItemMoveRequest:
            raise ValueError('A decoded exact current ItemMove request is required')
        self._context(request.source_loot_guid, ready_box_guids=ready_box_guids,
            references_resolved=references_resolved, exports_acknowledged=exports_acknowledged)
        binding = self._bindings[request.source_loot_guid]
        if (request.source_position != 302 or request.target_gids or request.target_loot_guids or
                request.source_weapon_gid or request.target_weapon_gid or
                request.source_space_guid or request.target_space_guid or request.spaces_to_sync_guids or
                request.allow_container_replace_backup or request.drop_container_items or
                request.force_replace_shell or request.command_owner_guid not in (0, self._player_actor_guid)):
            raise ValueError('This local branch accepts one mapped box whole-instance move into free cells')
        shape = self._original_items.get((binding.object_path, request.source_gid))
        if shape is None or request.move_count != shape[2]:
            raise ValueError('The requested whole-instance quantity differs from finite original contents')
        location = InventoryItemLocation(request.target_x, request.target_y,
            shape[0], shape[1], request.rotated, request.target_index)
        with self._lock:
            previous = self._requests.get(request.command_gid)
            if previous is not None and previous[0] != request:
                raise ValueError('The current CmdGid aliases a different native request')
            if previous is None and len(self._requests) >= 4096:
                raise ValueError('The finite native request journal bound is exhausted')
            receipt = self._authority.move_whole(player_id=self._recipient[1],
                cmd_gid=request.command_gid, box_path=binding.object_path, item_gid=request.source_gid,
                destination_position=request.target_position, destination_location=location,
                player_position=player_position, maximum_distance_cm=self._maximum_distance)
            self._requests[request.command_gid] = (request, receipt)
            return MoveDispatchResult(request, receipt,
                self._authority.box_snapshot(binding.object_path),
                self._authority.inventory_snapshot(self._recipient[1]))

    def project_box(self, box_guid, *, cursor):
        """Build the newest source delta against an actual ACK-committed cursor."""
        with self._lock:
            if box_guid not in self._bindings:
                raise ValueError('The mapped source box is outside the current dispatcher')
            binding = self._bindings[box_guid]
            snapshot = self._authority.box_snapshot(binding.object_path)
            return boxes.project(binding, snapshot.spaces, snapshot.items,
                recipient_scope=self._recipient, cursor=cursor)
