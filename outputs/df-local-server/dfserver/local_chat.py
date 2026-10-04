"""Read the local offline account's empty chat history without online peers.

PAK1 entry 6672 cs_chat_editor_pb.lua defines the world load and summary
contracts. FrontEndChatServer.lua entry 6872 0.53.0.0.0 advances its cursor
only for actual messages and changes rooms only for nonzero new_room_id.
ChatConfig.lua entry 2770 sets DEFAULTINTERVAL=20; ChatModule.lua entry
2772 0.25 adds load_msg_interval to that base delay in seconds.
"""

from .client_errors import error_code
from .core import DomainError


SUPPORTED_REQUESTS = frozenset({'CSWorldChatGetRoomIDReq', 'CSChatWorldLoadTReq',
                                'CSChatGetMsgSumyAllChannelReq'})
CLIENT_DEFAULT_INTERVAL_SECONDS = 20


def response_fields(request, backend, token):
    """Only queries are supported; there is no external messaging or room creation."""
    if request.name not in SUPPORTED_REQUESTS:
        return None
    try:
        with backend.connection() as connection:
            backend._authorize(connection, token)
        if request.name == 'CSWorldChatGetRoomIDReq':
            return {'result': 0, 'room_id': 0, 'is_student': False, 'college_room_id': 0}
        if request.name == 'CSChatWorldLoadTReq':
            cursor = int(request.fields.get('read_msg_index') or 0)
            if not 0 <= cursor < 1 << 63:
                return {'result': error_code('ChatInvaildReadMsgIndex')}
            return {'result': 0, 'msg_list': [], 'new_rooom_id': 0, 'new_room_id': 0,
                    'load_msg_interval': 0, 'rm_speech_playerid_list': [], 'rolling_notices': []}
        return {'result': 0, 'private_chat_sumys': [], 'group_chat_sumys': [],
                'private_chat_msgs_unread': [], 'team_chat_msgs_unread': []}
    except DomainError:
        return {'result': error_code('ChatPlayerNotLogin')}
    except (ValueError, TypeError):
        return {'result': error_code('ChatInvaildReadMsgIndex')}
