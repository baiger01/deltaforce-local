"""Recover installed SOL settlement enum, response consumers and return flow offline."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

import research_local_match_settlement as base
from offline_received_packet_xrefs import ImmutableImage

ROOT=Path(__file__).resolve().parent.parent
EXTRA_SOURCES={
    '@SettlementDataSOL.lua':'4933aa4daa5c81e460776487d5f31149739458b1344a1b9abd56a20523ae0c9d',
    '@SettlementField.lua':'d4200ea563397adfce514948e018ef45097b0c7fdb718dd707dba0a83caa1605',
    '@common_editor_pb.lua':'1248614d9907d1d8474efb58c3afffaf0bf0c93626b0865edf58e04fd5bd65d6',
    '@common_pb.lua':'81e071e35f33f0e5704d5098ac2a182c794bbe5b1e5a7e24f415a0473b40350b',
    '@zone2dsa_pb.lua':'9f76b18ed2ac131857f8628f3223eff594212eeb6d51cc1b8c2f571f75d7804b',
    '@ds_common_pb.lua':'6f1bec3a236dbd47c28d932a2702bc8cc386ecb6119312d71d57a62d6e8b8f6b',
    '@cs_settlement_pb.lua':'331c8f28788dec77890ede151eeb855bb5409c6f364e85c78dc683b231df1218',
    '@zone2dsa_editor_pb.lua':'14d9fa6ebed0c75fdcb4afc3b980ac44ef350dadce6ef5be3ae3d6cfc828adc2',
    '@DFMGlobalConst.lua':'4887a7f2b5265a5277c5c2553f4ff56ec08f1219a632220e3b2efa367baddcc4',
    '@InGameController.lua':'c944d3f0600f7bb990773776b93ab0db43ac1a13156a1ecf74af107c77e6ab36',
    '@SettlementLogic.lua':'d5206d013eda07b2f50a6e43317b2dfabef62c6b5c187bc6d1961fe74f8251ff',
    '@SettlementModule.lua':'dccc7a7962a293359fb93610931f7b0eddd31d2812360fe64cd4df3c031ea786',
    '@cs_settlement_editor_pb.lua':'a15c7536b8e5357e2723164f70d6003c498c8428be5c0bfda1d3d682c162f898',
}
ENUM_PATTERN=re.compile(r'ESettlementNtf|ESETTLEMENTNTF|SNTF_|GspPlayerGameStatusType|GSPPLAYERGAMESTATUSTYPE|GspPlayerResult|GSPPLAYERRESULT|EscapeResult|ESCAPERESULT')
CLIENT_SHA='4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CLIENT=Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')


def installed_facts(result):
    consumers={row['source']:row for row in result['lua_consumers']}
    def function(source,identifier):
        found=[row for row in consumers[source]['functions'] if row['function_id']==identifier]
        if len(found)!=1:
            raise ValueError('The exact installed settlement consumer function changed')
        return found[0]
    def reference(source,identifier):
        row=function(source,identifier)
        return dict(source=source,lua_sha256=consumers[source]['lua_sha256'],function_id=identifier,
            first_line=row['first_line'],last_line=row['last_line'])
    ds=function('@ds_common_pb.lua','0')['listing']
    modes={}
    outcomes={}
    for line in ds:
        match=re.search(r"SETTABLE\s+R1 K\d+='(SNTF_\w+)' K\d+=(-?\d+)$",line)
        if match:
            modes[match[1]]=int(match[2])
        match=re.search(r"SETTABLE\s+R1 K\d+='(kGspPlayerResult\w+)' K\d+=(-?\d+)$",line)
        if match:
            outcomes[match[1]]=int(match[2])
    if (len(modes)!=10 or not any("'ESettlementNtf' R1" in line for line in ds) or
            set(outcomes)!={'kGspPlayerResultEscaped','kGspPlayerResultKilled','kGspPlayerResultMissing',
                'kGspPlayerResultQuit','kGspPlayerResultGiveUp','kGspPlayerResultUndetermined'}):
        raise ValueError('The direct installed settlement enum assignments changed')
    common=function('@common_pb.lua','0')['listing']
    statuses={}
    for index,line in enumerate(common[:-1]):
        match=re.search(r"LOADK\s+R3 K\d+='(kGspPlayerGameStatusType\w+)'$",line)
        value=re.search(r'SETTABLE\s+R2 R3 K\d+=(-?\d+)$',common[index+1])
        if match and value:
            statuses[match[1]]=int(value[1])
    if len(statuses)!=3:
        raise ValueError('The literal installed game-status enum changed')
    messages=result['messages']
    def closure(root):
        found,missing=set(),set()
        pending=[root]
        while pending:
            name=pending.pop()
            if name in found:
                continue
            found.add(name)
            if name not in messages:
                missing.add(name)
                continue
            pending.extend(row['nested_type'] for row in messages[name]['fields'] if row.get('nested_type'))
        return dict(message_count=len(found),complete=not missing,missing=sorted(missing),messages=sorted(found))
    fields={name:[{key:field[key] for key in ('name','number','codec_category','nested_type','repeated')}
        for field in messages[name]['fields']] for name in (
            'CSSettlementEmptyNtf','CSSettlementGetNewSettlementInfoReq','CSSettlementGetNewSettlementInfoRes',
            'GspMatchInfoNew','MatchModeInfo','GspPlayerGameStatus','GspEndGamePlayerStatus',
            'GspQuitGamePlayerStatus','EquipPosition','PropInfo','CSStateClearSettlementReq',
            'CSStateClearSettlementRes','CSSettlementGetHasUnsettledMatchReq','CSSettlementGetHasUnsettledMatchRes')}
    return dict(
        actual_enums=dict(ESettlementNtf=dict(values=modes,source=reference('@ds_common_pb.lua','0')),
            EGspPlayerResultType=dict(values=outcomes,source=reference('@ds_common_pb.lua','0')),
            EGspPlayerGameStatusType=dict(values=statuses,source=reference('@common_pb.lua','0'))),
        generated_field_contracts=fields,
        response_schema_closure=closure('CSSettlementGetNewSettlementInfoRes'),
        installed_flow=[
            dict(step='notification_listener',source=reference('@SettlementServer.lua','0.10'),
                behavior='CSSettlementEmptyNtf is registered to OnReceiveSettlementNtf'),
            dict(step='notification_validation',source=reference('@SettlementServer.lua','0.25'),
                behavior='Require result == 0; if current MatchServer.GetDsRoomId() != 0 require identical room_id'),
            dict(step='notification_flow_gate',source=reference('@SettlementServer.lua','0.27'),
                behavior='Normal Game/GameSettlement fetch immediately; LobbyToGame/SafeHouseToGame defer; other unexpected flow fetches inventory, and GameToLobby retains SOL fetch path'),
            dict(step='sol_fetch',source=reference('@SettlementServer.lua','0.29'),
                behavior='ESettlementNtf.SNTF_SOL dispatches CSSettlementGetNewSettlementInfoReq and ParseSOLSettlementInfoGeneric/PostFetchSOLSettlementInfo'),
            dict(step='request_identity',source=reference('@SettlementServer.lua','0.40'),
                behavior='Request sets actual room_id and bNeedResendAfterReconnected=true'),
            dict(step='request_result_gate',source=reference('@SettlementServer.lua','0.41.0.0'),
                behavior='Only result == 0 resolves; failures retry then show retry/failure UI'),
            dict(step='sol_parse',source=reference('@SettlementServer.lua','0.71'),
                behavior='Require response.match_info; inspect match_info.mode_info.game_rule, construct SOL or SOLChallenge data, then sync season_change_info and cache data'),
            dict(step='sol_cache',source=reference('@SettlementDataSOL.lua','0.3'),
                behavior='Read match_info/player/team_info/teammate_array; require player.type in actual Playing/EndGame/QuitGame enum and select the matching playing/end_game/quit_game submessage'),
            dict(step='quit_or_cutscene',source=reference('@SettlementServer.lua','0.32'),
                behavior='QuitGame publishes settlement UI finished and returns; other results use next_is_musicfest or wait PlaySOLCutscene before _EnterGameSettlement'),
            dict(step='escaped_cutscene_gate',source=reference('@SettlementServer.lua','0.42'),
                behavior='Only player.result == kGspPlayerResultEscaped waits current Pawn.PlayerExitComponent.PlayCutSceneBeforeSettlement completion delegate; absent Pawn/component resolves with warning'),
            dict(step='native_gameflow_bridge',source=reference('@SettlementLogic.lua','0.29'),
                behavior='While current flow is Game, call DFMSettlementManager.Get(GetWorld()).BroadcastChangeGameFlow2GameSettlement()'),
            dict(step='gameflow_entry_consumer',source=reference('@SettlementModule.lua','0.23'),
                behavior='On entering GameSettlement call _GameSettlementMainEntry(GetSettlementInfoSource()); on Lobby reset fail-safe and publish start-to-show-settlement'),
            dict(step='clear_business_settlement_flag',source=reference('@SettlementModule.lua','0.60'),
                behavior='Send empty CSStateClearSettlementReq; response result field1 is uint32'),
            dict(step='return_lifecycle',source=reference('@SettlementLogic.lua','0.48'),
                behavior='Publish end event, restore resources and clear settlement flag, then call native SettlementEndBroadcast and await leave GameSettlement plus enter next gameflow'),
            dict(step='post_return',source=reference('@SettlementLogic.lua','0.50'),
                behavior='OnSettlementEnd, ResetSystemReconnectState and release map resources'),
        ],
        parallel_native_match_over=dict(listener=reference('@SettlementLogic.lua','0.10'),
            consumer=reference('@SettlementLogic.lua','0.14'),
            delegate='DFMGameplayDelegates.Get(World).OnClientPlayerMatchOver',
            reason_type='EMatchOverReason',
            notification_does_not_itself_prove_this_delegate_was_received=True),
        exact_cutscene_delegate_names=['ClientNotifyLocalPlayerExitMeidaEnd','ClientNotifyLocalPlayerExitSequenceEnd'],
        required_result_projection=[
            'Use the stored actual match/player/room identity for notification, fetch and carry records',
            'Populate match_info.mode_info from the actual admitted mode, not EmptyNtf.mode (which is the settlement routing enum)',
            'Populate player.type and exactly its matching status submessage from the real terminal state',
            'Populate player.result from the actual extraction/death/quit outcome; escaped enum value 0 is not an implied default success',
            'For EndGame provide actual season_change_info; the parser reads it before UI entry',
            'Carry-in and carry-out records are EquipPosition arrays with actual position/load_props/capacity/grid_space/src_prop_id; preserve PropInfo GIDs, quantities, condition, weapon, components and location',
            'Materialize authoritative final inventory before sending EmptyNtf because unexpected-flow consumers may immediately FetchAllItems',
            'Read/retry/query/delete_room_id/clear-settlement requests must not recommit rewards or change terminal result',
        ],
        missing_native_end_contracts=[
            dict(boundary='authoritative extraction/death to client match-over',
                missing='Exact incoming native receiver and serialized EMatchOverReason/current PlayerSettlementComponent layout; Lua delegate subscription is not that wire contract'),
            dict(boundary='escaped player cutscene completion',
                missing='Current PlayerExitComponent state/config plus source-qualified PlayCutSceneBeforeSettlement prerequisites and native completion behavior; business success must not fabricate the completion delegates'),
            dict(boundary='native settlement manager travel',
                missing='Native implementations/current state of BroadcastChangeGameFlow2GameSettlement and SettlementEndBroadcast plus any server connection-close/return requirements; Lua local calls are source-backed but no native packet acceptance is claimed'),
        ],
        native_end_receiver_qualified=False,
        business_notification_and_response_field_contracts_qualified=True,
        result_saved_before_notification_required=True,
        empty_success_response_is_sufficient=False,
        service_or_account_writes_performed=False,
    )


def native_enum_records(executable=CLIENT):
    """Inspect only immutable read-only initialized data and native enum pairs."""
    prefix=b'ESettlementNtf::'
    with Path(executable).open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=CLIENT_SHA:
            raise ValueError('The pinned immutable installed client changed')
        with mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as data:
            image=ImmutableImage(data)
            nt=struct.unpack_from('<I',data,0x3c)[0]
            table=nt+24+struct.unpack_from('<H',data,nt+20)[0]
            sections=[]
            for index in range(struct.unpack_from('<H',data,nt+6)[0]):
                at=table+index*40
                _,rva,size,raw=struct.unpack_from('<4I',data,at+8)
                flags=struct.unpack_from('<I',data,at+36)[0]
                if rva==0x14d03000 and size==0x7cfaa00 and flags==0x40000040:
                    sections.append((rva,bytes(data[raw:raw+size])))
            if len(sections)!=1:
                raise ValueError('The pinned read-only initialized-data section changed')
            rva,raw=sections[0]
            literal_hits=[]
            for text in ('SNTF_SOL','ESettlementNtf'):
                for encoding in ('ascii','utf-16-le'):
                    needle=text.encode(encoding)
                    at=raw.find(needle)
                    count=0
                    while at>=0:
                        count+=1
                        if count>128:
                            raise ValueError('The exact native settlement literal scope exceeded its bound')
                        literal_hits.append(dict(text=text,encoding=encoding,rva=hex(rva+at)))
                        at=raw.find(needle,at+1)
            def name_at(pointer):
                try:
                    return image.read(pointer-image.image_base,128).split(b'\0',1)[0]
                except ValueError:
                    return b''
            strings=[]
            target=prefix+b'SNTF_SOL\0'
            at=raw.find(target)
            while at>=0:
                strings.append(rva+at)
                at=raw.find(target,at+1)
            records={}
            for text_rva in strings:
                pointer=struct.pack('<Q',image.image_base+text_rva)
                at=raw.find(pointer)
                while at>=0:
                    first=at
                    for _ in range(64):
                        if first<16 or not name_at(struct.unpack_from('<Q',raw,first-16)[0]).startswith(prefix):
                            break
                        first-=16
                    entries=[]
                    for offset in range(first,min(len(raw)-16,first+64*16),16):
                        text,value=struct.unpack_from('<Qq',raw,offset)
                        name=name_at(text)
                        if not name.startswith(prefix):
                            break
                        entries.append(dict(name=name.decode('ascii'),value=value,text_rva=hex(text-image.image_base)))
                    if any(row['name']=='ESettlementNtf::SNTF_SOL' for row in entries):
                        pairs=raw[first:first+len(entries)*16]
                        records[first]=dict(pairs_rva=hex(rva+first),pairs_sha256=hashlib.sha256(pairs).hexdigest(),entries=entries)
                    at=raw.find(pointer,at+1)
            return dict(client_sha256=CLIENT_SHA,section_rva=hex(rva),section_bytes=len(raw),
                section_flags='0x40000040',exact_name_rvas=[hex(v) for v in strings],
                name_value_tables=list(records.values()),literal_hits=literal_hits,disk_executable_code_read=False)


def windows(lines,pattern,before=5,after=12):
    intervals=[]
    for at,line in enumerate(lines):
        if pattern.search(line):
            start,end=max(0,at-before),min(len(lines),at+after+1)
            if intervals and start<=intervals[-1][1]:
                intervals[-1]=(intervals[-1][0],max(end,intervals[-1][1]))
            else:
                intervals.append((start,end))
    return [dict(first_instruction=start+1,last_instruction=end,listing=lines[start:end])
        for start,end in intervals]


def derive():
    previous_sources,previous_roots=base.SOURCES,base.MESSAGE_ROOTS
    try:
        base.SOURCES=dict(previous_sources,**EXTRA_SOURCES)
        base.MESSAGE_ROOTS=previous_roots|{'CSSettlementEmptyNtf'}
        result=base.derive()
    finally:
        base.SOURCES,base.MESSAGE_ROOTS=previous_sources,previous_roots
    result['kind']='offline_installed_sol_settlement_end_to_lobby_flow_v2'
    result['sources']['work/research_local_match_settlement.py']=hashlib.sha256(
        (ROOT/'work/research_local_match_settlement.py').read_bytes()).hexdigest()
    result['sources']['work/research_local_settlement_flow_v2.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result['native_settlement_enum']=native_enum_records()
    result['qualified_flow']=installed_facts(result)
    for consumer in result['lua_consumers']:
        if consumer['source'] in ('@common_editor_pb.lua','@common_pb.lua','@zone2dsa_pb.lua',
                '@ds_common_pb.lua','@cs_settlement_pb.lua','@DFMGlobalConst.lua'):
            chosen=[]
            for function in consumer['functions']:
                selected=windows(function['listing'],ENUM_PATTERN)
                if selected:
                    chosen.append(dict(function_id=function['function_id'],first_line=function['first_line'],
                        last_line=function['last_line'],instruction_windows=selected))
            consumer['functions']=chosen
            consumer['unrelated_enum_listing_omitted']=True
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT/'work/evidence'):
        parser.error('Use a fresh evidence output inside this project')
    report=derive()
    raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode()
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(path=str(args.output),sha256=hashlib.sha256(raw).hexdigest(),
        lua_sources=len(report['lua_consumers']),messages=len(report['messages']))))
