"""Launcher zone discovery shape recovered from the public GetZone endpoint.

This advertises loopback routing only. It supplies no account authentication,
transport handshake, or game login response.
"""
import json
import threading

from .core import DomainError


GET_ZONE_PATH = "/api/v1/wegame.rail.game.RepoSVC/GetZone"


class ZoneDiscovery:
    def __init__(self, game_port=65010):
        if type(game_port) is not int or not 1 <= game_port <= 65535:
            raise ValueError("Invalid loopback game port")
        self.game_port = game_port
        self._requests = 0
        self._lock = threading.Lock()

    def reply(self, request):
        if request.get("game_id") != "2001918" or request.get("from_src") != "launcher":
            raise DomainError("INVALID_ZONE_REQUEST", "Expected the supported game and launcher source")
        zones = []
        for zone_id, label, channel_marker in (
                (101, "QQ", "hide_in_nonqq"), (102, "微信", "support_wxoauth")):
            identity = str(zone_id)
            metadata = {channel_marker: 1, "zone_id": identity, "parent_zone_id": "0"}
            zones.append({
                "game_id": "2001918", "zone_id": identity,
                "zone_id_str": f"{zone_id}.0.0.0", "parent_zone_id": "0",
                "zone_name_zh_cn": f"{label}（本机连接测试）",
                # A known release key causes Lua to ignore the supplied address.
                "zone_name_en_us": "df_local_loopback",
                "zone_description_zh_cn": "本机连接测试；大厅尚未验证",
                "zone_description_en_us": "Local connection test; lobby unverified",
                "bind_branch": "[1]",
                # Native code parses this string as a JSON array, then joins it.
                "server_ips": json.dumps([f"127.0.0.1:{self.game_port}"], separators=(",", ":")),
                "metadata": json.dumps(metadata, separators=(",", ":")),
                "is_visable": 1, "is_joinable": 1, "is_flat_structure": 1,
                "zone_sequence": zone_id - 77, "zone_state": 1,
                "activted_time_bj_in_unix": 0, "leaf_node": "true",
                "data_from_source": "local", "extra_meta_data": [
                    {"key": channel_marker, "value": "1"}],
            })
        with self._lock:
            self._requests += 1
        return {"result": {"error_code": 0, "error_message": "success"},
                "zone_info": zones, "zone_support_role_query": 0}

    def status(self):
        with self._lock:
            requests = self._requests
        return {"stage": "discovery_only", "requests_total": requests,
                "game_endpoint": f"127.0.0.1:{self.game_port}",
                "original_client_connection_verified": False,
                "game_compatibility_verified": False}
