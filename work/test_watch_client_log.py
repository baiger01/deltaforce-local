"""Keep native map entry transitions and failures in the live alert log."""

from pathlib import Path
import tempfile
import unittest

from watch_client_log import follow


class MapEntryLogTests(unittest.TestCase):
    def test_optional_entry_observer_receives_lines_before_alert_filtering(self):
        class Observer:
            def __init__(self):
                self.lines, self.resets = [], 0

            def observe_line(self, line):
                self.lines.append(line)

            def reset(self):
                self.resets += 1

        observer = Observer()
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / 'client.log', Path(folder) / 'alerts.log'
            source.write_bytes(bytes(value ^ 0x5c for value in b'ordinary non-alert line\n'))
            count = follow(source, target, 0, from_start=True, observer=observer)
        self.assertEqual(observer.lines, ['ordinary non-alert line'])
        self.assertEqual(observer.resets, 1)
        self.assertEqual(count, 0)

    def capture(self, lines, *, bom=True):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'client.log'
            target = Path(folder) / 'alerts.log'
            raw = ('\n'.join(lines) + '\n').encode('utf-8')
            source.write_bytes((b'\xef\xbb\xbf' if bom else b'') +
                               bytes(value ^ 0x5c for value in raw))
            count = follow(source, target, 0, from_start=True)
            return count, target.read_text(encoding='utf-8')

    def test_map_entry_stages_and_terminal_network_failure_are_retained(self):
        lines = [
            '[23:32:15] LuaSTeam: TeamServer:SendPersonMatchingWithParams_Success, 0',
            '[23:32:35] LuaSMatch: MatchServer:_OnCSPrepareJoinMatchNtf client_group, 0',
            '[23:32:45] LuaSMatch: CSMatchRoomSolReadyTReq',
            '[23:32:56] LogSeamlessEnter: TryConnectDS, real start connect ds!!!',
            '[23:33:00] LogNet: SerializeNewActor PlayerController',
            '[23:34:00] LogNet: UEngine::BroadcastNetworkFailure ConnectionTimeout',
        ]
        count, output = self.capture(lines)
        self.assertEqual(count, len(lines))
        for line in lines:
            self.assertIn(line, output)

    def test_native_connection_url_is_retained_without_option_values(self):
        _, output = self.capture([
            'LuaSMatch: [GetLevelUrlAsync] url = 127.0.0.1:61282'
            '?PlayerId=6311504805269387056?Cookie=private-cookie?MapId=2201',
            'LuaSMatch: CSPlayerJoinMatchNtf secret_key=private-key ticket: private-ticket',
        ], bom=False)
        self.assertIn('[GetLevelUrlAsync]', output)
        self.assertIn('?Cookie=[redacted]', output)
        self.assertIn('?MapId=[redacted]', output)
        self.assertNotIn('6311504805269387056', output)
        for value in ('private-cookie', 'private-key', 'private-ticket'):
            self.assertNotIn(value, output)

    def test_department_requests_and_task_panel_state_are_retained(self):
        lines = [
            'LuaSQuest: Error: [QuestServer] GetNotifyQuestRebirthWeekly, invalid rebirthline',
            'LuaSQuest: CSQuestAcceptReq quest_id=49001',
            'LuaSQuest: CSQuestGetAcceptedQuestsRes count=5',
            'LuaSBlackSite: CSSafehouseSubmitUpgradePropReq device_id=1010',
            'LuaSBlackSite: BlackSiteDevice CheckConditions',
            'LuaSAttribute: CSAttrGetAllQualityReq',
            'LuaSAttribute: CSAttrQualityValueChangeNtf',
            'LuaSAttribute: CSAttributeGetConfigRes',
            'LuaSAccount: CSAccountExpChangeNtf',
            'LuaMSandBoxMap: [SandBoxMapView] show task:true,questList count=1,mapId:2201,bIsBoss:false',
        ]
        count, output = self.capture(lines)
        self.assertEqual(count, len(lines))
        for line in lines:
            self.assertIn(line, output)

    def test_local_character_binding_and_range_events_are_retained(self):
        lines = [
            'LogGPCharacter: ADFMPlayerController::OnPossess Pawn Name = BP_DFMCharacter_SafeHouse_C_1',
            'LogGPCharacter: GPPlayerController::AcknowledgePossession PawnName=BP_DFMCharacter_SafeHouse_C_1',
            'LogKeySetting: DFHDKeySettingMgr::OnEnterRange(), 1',
            'LuaMRange: Error: RangeLogic._DebugPrintDisplayInput()',
            'LogGPCharacter: TryReborn Character Name=BP_RangeTargetCharacter_C_1',
        ]
        count, output = self.capture(lines)
        self.assertEqual(count, len(lines))
        for line in lines:
            self.assertIn(line, output)

    def test_native_world_initialization_and_player_sync_are_retained(self):
        lines = [
            'LogGPGame: AGPGameMode::InitDSLogic',
            'LogDFM: ADFMGameMode::InitGame DFMDSLogic Is Null !',
            'LogDFM: Failed to conver GameState to ADFMGameState',
            'LogDFM: PlayerInfo is not found with PlayerID[123]',
            'LogDFM: PlayerState is not ADFMPlayerState type',
            'LogDS: Receive pb.Any2DsSyncPlayerInfoReq',
            'LogDS: SDsaSyncPlayerInfoReq:count=1',
            'LogDS: UDFMDSLogic::ProcSyncPlayerReq Add DsPlayerInfo',
            'LogDS: PreProcSyncPlayerHalfJoinReq Fial!',
            'LogDS: SDsaSyncPlayerInfoReq:ds_token.empty(), PlayerId=123',
        ]
        count, output = self.capture(lines)
        self.assertEqual(count, len(lines))
        for line in lines:
            self.assertIn(line, output)

    def test_async_image_failures_are_retained_without_success_noise(self):
        failed = (
            'LuaFManager: Error: >>>> xhz >>>> '
            'ResImageUtil.AsyncLoadImgObjByPath.fOnImageLoadFinished: '
            "Resource load failed:, Texture2D'/Game/UI/UIAtlas/Texture/HeadAvatar/"
            "HeadAvatar_0000.HeadAvatar_0000'"
        )
        successful = (
            'LuaFManager: Display: ResImageUtil.AsyncLoadImgObjByPath.'
            'fOnImageLoadFinished: Resource load succeeded'
        )
        count, output = self.capture([failed, successful])
        self.assertEqual(count, 1)
        self.assertIn(failed, output)
        self.assertNotIn(successful, output)

    def test_native_connection_binding_and_seamless_travel_are_retained(self):
        lines = [
            'LogGPNet: Display: UGPNetConnection::HandleClientPlayer',
            'LogGPNet: Display: UGPNetConnection::HandleClientPlayer  Super',
            'LogGPNet: Display: IGPSeamlessConnectionInterface::HandleClientPlayer  SeamlessTravel',
            'LogGPNet: Display: IGPSeamlessConnectionInterface::HandleClientPlayer  SeamlessTravel with NetActorRemapping',
            'LogNet: VeryVerbose: Client received PlayerController=BP_PlayerController_C_1. Num child connections=0.',
            'LogNet: VeryVerbose: BP_PlayerController_C_1 setplayer LocalPlayer_0',
        ]
        count, output = self.capture(lines)
        self.assertEqual(count, len(lines))
        for line in lines:
            self.assertIn(line, output)


if __name__ == '__main__':
    unittest.main()
