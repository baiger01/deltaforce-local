# 世界交互、地图事件与真实终局重新调研

本报告只读 `deltaforce-map-appearance` 的现有代码、原客户端提取物与已保存观测，没有启动游戏、访问运行进程、发送报文、修改诊断源或数据库。输出为本报告、`work/evidence/gameplay-world-research-20261020.json`及后续明确授权的只读研究脚本`work/research_world_admission_20261020.py`。初稿代码快照核对时间为 2026-10-20 07:15:59Z；各次收尾复核另见 JSON。原生证据限定于客户端 SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`、代码缓存清单 `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。范围普查于07:29:24Z重验原客户端完整SHA并只读扫描rdata；08:26:27Z之后的追加直接恢复原始PAK准入表，没有重新采集运行时代码或声称整份安装/当前热更新都已验证。

## 结论与范围

现有资料足以否定“地图玩法已经调研完整、只差接几个消息”。三种状态必须保留：已经进入真实发送链的出生/Prepare事件/高价值投影；独立实现的箱体codec、原生请求decoder、有限库存SQL事务和ACK outbox；仍缺真实生产者的世界绑定、锁权限、搜索计时、普通门/卡门、散落物、任务事件、曼德尔世界状态和撤离终局。`portable_durable_world_runtime.install_runtime` 第165–203行当前无条件返回 `RuntimeInstallation(False, None, reasons)`，明确缺 PackageMap provider、permission provider、箱体世界位置与 terminal authority。给它传字典、回执或恒真callback不会形成合法接线。

本域已发布的实际地图入口仅有 `protocol/local_map_board_candidates.json` 的 `2201 / Dam_Iris_Level1 / match_mode_id=142201103`。后续原表恢复已闭合六图的真实静态`MatchModeDataConfig -> MapConfig -> SubWorld`关联，见末节；它没有扩大已发布和原生验收范围。本文的三保险箱、旧门候选、八出口、Long3共享资源及普通/Trials曼德尔包均有特定地图边界。各图仍需完成“实际发布point_id/模式 -> 当前生效配置/加载资源 -> 活跃Actor -> 出口/事件/任务 -> receiver -> 原生操作”矩阵。MapInfo表中的 `MapConfigMapID`、原生 `MapType`、门卡 `MapID`、业务 admission `map_id` 是不同命名空间。

SOL、MP、Trials也不共用一个终局模板。已恢复业务路由 `SNTF_SOL=3`、`SNTF_SOLChallenge=6`，普通SOL与挑战的构造还看 `match_info.mode_info.game_rule`；MP需选其真实模式分支。`ESettlementNtf`不能代填`MatchModeInfo`。`BP_SOLPlayerState`的170/171不能在未核对接收类时推广到MP。

## 当前原生证据，按时间区分

以下均为试验 `1792478435036855300` 已保存文件；文件哈希、UTC时间及字段级内容见配套JSON。

- `06:44:42Z`的初次membership报告因传入report路径不在`work/native-client-tests`而拒绝。它只证明观察器路径契约冲突。协作者可能继续修订，不能把这条旧拒绝写成最新代码仍未修复。
- `06:47:35Z`的tag观察为`observed`：当前`GameplayTagsManager +0x181`实收`00`、nonfast=true，身份、模式及owned roots均复查。该时点可用普通FName分支；不是所有新进图永久不再检查模式。
- `06:50:15Z`地图观察为`partial`，但若干单项确实读取成功：`HighValueBoxInfoArray count=2/capacity=4`，未读元素；`AZHighValueZoneInfoArray count=0`；`AllocatedExits count=0`；任务数组count=0、`bQuestInited=false`；`BlueprintPlunder`为typed声明对应的null；`InteractSystemComponent`为typed existing reference。
- 同一地图观察中的`CachedInteractableComponents`、`MapDoorInfoArray`、`bUseGridBasedManagement`、`bUseSceneQuery`因实际flags/type与scope不符而拒绝。它们不是空数组或false，不能据此选择修复值。
- `06:53:22Z`world lifecycle因超过64个未能资格确认的候选而拒绝；不是证明没有交互Actor。
- `06:53:48Z`RPC元数据确认当前PC226、InventoryManager45、SOLInteractor71/72的owner及索引；本轮这些UFunction仍标`missing_uninitialized_native_serial/layout=missing`。历史`1792401899578422100`有真实ItemMove函数布局。serial零不是函数不存在，旧函数布局也不等于本轮已经执行了请求。
- `06:54:57Z`membership retry找到三个精确保险箱实例，class/path/Outer、`World.Levels`、`ULevel.OwningWorld`及visible bit成立。`World.Levels count=434/capacity=584`，不能把capacity当实际元素数。没有匹配`StreamingLevels.LoadedLevel`，旧门`BP_Interactor_RotateDoorBase13`本轮not_found，`native_actor_binding_verified=false`。
- `07:11:19Z`GUID retry因`The actual trial frozen profile source changed`拒绝；不能由原计划NetGUID或静态路径宣称当前PackageMap映射已成立。

## 世界、流式层与Actor身份

原生主世界仍可叫`Iris_Entry`，不能因此判定进错地图。已有只读`qualified-findings.json`记录：Iris_Entry WorldSettings `MapType=14 / bContainsSubWorld=true / SubWorldConfigTable=DT_SubWorldConfig_Iris_Entry`；Dam Level1静态WorldSettings `MapType=10 / bEnableLooting=true`。实际表81行中`Dam_Iris_Level1`序列化偏移2673，类别SOL，LevelSubsystemConfig=-9；`Iris_Entry`偏移7272。初次选行报告未解析soft-object，后续本轮已从原表FName/FString及UAsset import链精确恢复六图规则与子系统路径，见末节；不是将十六进制索引猜成资产路径。

`DefaultOpenWorldTileSettings.ini`行413将`Dam_Iris_Long3`关联多个Dam变体；CookedTiles Level1/Long3分别包含目标Gameplay、Loot、InnerLoot包的FString记录，但Iris_Entry.bin没有这些包。它证明静态关联，不证明当局加载。retry已进一步证明两个箱体Level在当前World.Levels中且可见；它没有闭合目前观察器额外要求的StreamingLevels关系。这个条件可能还需沿SubWorld/世界组合的真实加载分支恢复，不能简单改为恒真，也不能反向声称箱体必然未加载。

生产绑定应同时固定：admission/room_seed/transport generation；当前PC/Pawn/World roots；Actor精确class、完整cooked路径、Outer Level、当前Level归属/可见性；本次PackageMap GUID -> typed Actor及ActorChannel；导出真正发送/ACK和失败Control16；生命周期变化后的失效/重新绑定。对象存在、网络ACK、加载页图标均不足。静态关卡Actor不得再spawn一个同名动态副本。服务器动态拾取/尸体/事件Actor使用单独GUID命名空间。

位置必须从同一局被服务接收提交的移动状态与真实世界原点/关卡变换得到；客户端`OriginPosByClient/OriginPos1P`只是输入。`ControlOwner.accepted_position`读取`accepted_movement_position`是已有适配点，但接受移动报文不自动证明碰撞、导航或穿墙限制。箱体坐标不能直接取未换算的静态导出平移或任意填零。

## F交互、门与门卡

实际入口是Pawn的`/Script/SOL.SOLInteractorComponent`：`ServerExecuteInteractByTag` index71/max168，原生exec`0xcec12e0`；`ServerInteractAction` index72，exec`0xcec1560`。两者含Actor引用与`FGameplayTag`；71另含52字节`InteractingContext`。客户端聚焦还依赖当前Pawn的Interactor owner/blackboard、本地控制、GameState InteractSystem的注册与查询，而不是“发了Interactor空块”即有F提示。

`portable_world_interact_request.schema/decode_field`已独立恢复非fast tag路径：CppOps wrapper`0x1242c500 -> 0x12427750 -> 0x12427940`，`+0x181==0`走`0x12427e69`的FArchive FName。Context是反射普通结构，含开门方向、五个int32、两Vector、四bool及DialogueSelectIndex；388叶子bit不包括外层参数存在位。当前decoder只接受三个资格保险箱映射和源SafeBox标签，并非通用门decoder。

普通门cooked类`BP_Interactor_RotateDoorBase`明确有`Door.Open / Door.Close / Door.ReleaseLock`标签、前后交互点及Tag到process映射。状态侧`SwitcherStateWithContext`原生结构record`0x1d22d340`、56字节，Context偏移4；bool由setter`0xd903b0`给出，不能根据native结构大小猜RepLayout。尚需本局真实门Actor、Lock/OpenClose组件receiver handles、状态enum、正常OnRep/碰撞/动画消费者及可靠结果。

门卡目录334模板来源可读，例`15050100001`行0/序列化偏移71为map_id22、durability20，不能据它发给某扇门。现存目录也明确“不模拟门交互”。必须恢复门锁要求 -> 卡模板/地图/等级 -> 当前卡GID与剩余耐久 -> 服务权限 -> 单次消耗 -> 同事务解锁 -> 卡与门两侧复制。缺卡、错卡、耐久零、重复F/重传、已开门再用卡的结果各自固定；卡包分区不是实际门身份。不能用大厅存档中“拥有卡”代替本局已携带卡。

额外交互不能被遗漏：SafeBox资源名表确有`InteractorGeneratePasswordComponent / PasswordEveryBodyNum / SafeBox.ReleaseLock`；这仍只是组件/标签来源，密码生成、请求、验证及解锁状态未接。原生字符串还有破坏组件`UInteractorProcessDestructableComponent`（RVA`0x1842a4d0`）和雷达电梯process/switcher（`0x17b9e950 / 0x17ba0c00`），航天电梯含外门/内开关、堵门与阶段拒绝日志（`0x1a6f0a10..0x1a6f1230`）。这些名字不是RPC或完整执行证明。追加范围普查又直接找到索道Actor、报告请求及OnRep声明，详见末节；仍未闭合其资产、输入、receiver和权威执行，不能标为不存在或复用电梯处理。

## 开箱、搜索与物品移动

客户端`LootingServer.lua 0.42`（源码872–919，块hash`9ff7b3b8a802c30cc44dd2aaca3ff98e369c9e678dcbe33b1b675c6a62ae9ee2`）从当前交互箱和当前角色InventoryManager构建looting状态并`RequestSetIsLooting`，不是大厅仓库协议。PC `ServerOpenPickupBox`为index226/max245，参数是`InventoryPickup_OpenBox`对象；exec`0xced9a80`、实现`0xb58f9c0`。独立one-object decoder尚需真实当前GUID映射/owner gate。

箱体独立receiver不能借InventoryManager索引：已封存SafeBox有`LootBoxRepData h103`、`bIsEmpty h113`、`RepItemArray cache55 / exclusive max85`。`LootBoxRepData`是24字节多态wrapper，array在+8；真实CppOps表`0x18867070`、wrapper`0xcfd5960`、body`0xcfd5fa0`、space`0xcfd5c00`、客户端网格派生`0xc21e0f0`。源SafeBox CDO UAsset hash`8da4241c...`、uexp`ed3b2ebb...`，容量4x4、InventoryIdName=`99010000021`、BoxID920、BaseItemSearchTime=3。3是源字段，不能直接宣布所有物品/模式固定3秒搜索。

有限种子producer只支持三个无容量覆盖的保险箱，真实GameItem形状/最大堆叠、调用方预留GID、真实4x4容量，格ID1是明确本地实例策略。枪械/装备/门卡等需完整特征的物品会拒绝；不能把局内全物资归结为这三个箱子。搜索还缺CurrentSearchingPlayers、CurrentLootingPlayers、SearchDonePlayer、占用/中断/逐物揭示及时间权威；当前dispatcher的“立即open本地策略”没有恢复这些行为。

`InventoryManager.ServerProcessItemMoveCmd` index45/max53，exec`0xcfbc2c0`、impl`0xbfc43f0`。服务原生实现`0xbfc491f`会用自身OwnerCharacter覆盖CmdOwner。已有decoder沿`1792401899578422100`真实layout恢复两个parent、34command、CmdGid/SourceGid/TargetGids、源/目标位置与格子、对象引用、旗标及Vector；328 native字节不是线字节。SourcePos/TargetPos使用真实EAttachPosition的27bit语法，数组数16bit；CmdOwner和客户端位置不授予所有权/距离。

现有`DurableWorldDispatcher.move_request`只接“箱 -> 明确空格子、完整整堆普通实例”；拒绝拆分、合并、交换、装备槽、自动摆放、容器连带、枪配件/弹药生命周期、地面丢弃/拾取。SQL按admission+CmdGid保存native请求和不可变结果，改变请求重用CmdGid拒绝；同事务移动owner、保留原GID/数量/特征、更新两侧revision。不能把整堆成功泛化为全部背包操作。

回复链已独立实现：有限箱delta -> 真实箱ACK -> owning库存delta -> 真实库存ACK -> `ClientNotifyItemMoveResult` RPC22/max53 -> 真实结果ACK。结果enum6bit，MoveExtraInfo省略以保留原生默认，无原生接收通过记录。掉包/重连时重放已提交结果，不重新抽箱、不重复移动。ACK只推进outbox/基线；不证明格子、搜索、拿取实际可用。

地面拾取还需真实`AInventoryPickup` class/CDO/layout、`PickupItemInfo`及`OnRep 0xc1627e0`、角色InventoryManager、源目标空间和Actor毁灭/empty更新。丢弃是player -> world的反向权威事务，必须生成有归属的一份Actor和实例；重拾恢复相同实例/特征，partial-stack才分配新GID。现无完整生产执行链。

## 物资、标记、任务与曼德尔

当前本地规则允许自定义概率/数量，不要求恢复官方爆率；真实ID、源形状/特征、总量预算与冻结config/seed仍必须校验。`legacy_ds_local_map_rules`生成世界策略，不能单独生成可互动Actor。三个SafeBox seed、散落物、AI尸体、任务物、稀有物和曼德尔分别需要类型完整producer，共享唯一实例分配与物品owner账。

高价值链已接入：真实rule snapshot重放 -> `FrozenHighValueMarkers` -> GS `SOLMapInfoSystem.HighValueBoxInfoArray h8`；ordinary子handle与结构有已封存schema。`freeze_high_value_markers`保留`runtime_actor_resolved=false`，生成图标不创建箱体/任务/出口。最新count2只证明数组头有两个元素；还需逐元素比对被冻结选择、真实坐标变换及大/小地图/HUD UI。不得将未解析Actor的候选标记当可开箱实体。`GuideGetWidgetLogic 0.6/0.6.0`真实消费者读MapInfo/viewcontroller中的bHighValueBox/IconType/ColorType/Desc，块hash`02392a26...`。

任务初始请求已在`MatchServer.lua 0.104`（2092–2581，hash`4ec5c828...`）出现RequestAcceptedQuests；正式地图消费者是PS的`MapInfoComp`：QuestObjectionTrackerArr h15、bQuestInited h16、MapQuestLocationDataArray h17、CurrentTrackedQuestObjectiveID h18。最新实值为未初始化/空，尚需admission冻结任务与版本、真实区域/目标实例映射、权威事件驱动进度、失败/中断/撤离依赖、奖励唯一提交。任务标点和大厅已接任务不是任务完成。

曼德尔Prepare链已有源：`box_event field12 -> MandelSpawnerIDArray`、`iris_event_ids field15 -> EventIds`，使用同局seed/生成结果。Long3共享包中八生成器、二十四候选解码器；另一套Level51是ETrialsMode。已解析本地源汇总有16解码位置、32高价值项/25唯一坐标；这些口径不是同一集合。`DefaultDecipherDuration=180`、`DefaultWaitingRecycleDuration=60`仍需当前逻辑覆盖/单位与复制核验。原生RNG/权重片段不恢复事件生命周期。

世界链必须是GS真实`BlueprintPlunder h106`和`MandelBrickID h71` -> 选中发生器/砖实例 -> BeingWanted/持有队伍/掉落/再拾 -> Deciphering与权威timer -> WaitingRecycle/争夺 -> BeTakenOut -> 同终局物品账。GS引用本轮null，故Prepare不等于世界事件已运行。PS MandelBrickNums h149、Trials h165–168等为不同分支，不能以普通字段捏造Trials成功。大厅抽奖扫描的池和“开砖奖励”与地图生成/携带/解码/带出完全分开。

## 撤离条件与计时

来源是`Dam_Iris_Level1_GameplayConfig.umap`，UAsset SHA256`ae166aaf05cc5baaf18b55eb2ac78e6f426a0fb367ffc9b9becba364fcbd31ce`、uexp`da7418c8f6df634e04e3a06513aaceb598b016d085e16b530a13d91dcada813a`。已读取export33–40：201水闸、101/102/104/106普通、103负重、105装备、107付费。静态候选不代表本局全部开启。

- 201（export33）ExitMethodConfig偏移18831：Together/CountDown180；ExitOpenConfig偏移18688：Switch，引用27/26；awake限制360、close180、reset2也有源。需恢复真实开关Actor/触发、范围与reset状态，不是“等180秒自动成功”。
- 103（export38）ExitConditionConfig偏移26528：RoleLoadLimit范围0..50；checkers177/178为RoleLoad及Not版本。不能只按截图负重或静态Bag空字段判断。
- 105（export39）偏移28184：EquipmentLimit/Bag/Empty；checkers168/169为Equipment及Not版本。需用真实服务库存与装备状态。
- 107（export40）条件偏移29787：Payment10000，付款interactor32；方法偏移30065为CountDown30；关闭配置偏移30151为AfterEscapeCount4。扣款类型、重复付款、失败退款及占位需要原生消费者/本地明确规则，不能从数字猜经济币种。
- 普通出口若省略CountDown/ExitOpenType等字段，应读父类/CDO和运行覆盖。不能把107的30秒填给所有普通出口。

服务器按同局分配写PS `AllocatedExits h187`的真实Actor引用，并同步各出口awake/open/使用人数/条件/倒计时。tick必须基于单调服务器时间并保存可恢复deadline；移动离开/死亡/条件失效/关闭/重连后的取消与继续均由该出口规则决定。只有资格、范围、条件与完成时间均通过且玩家仍active，才生成一个不可替换terminal intent。当前并无这些出口权威执行器，最新AllocatedExits为空。

## 终局、结算UI与回大厅

终局有两条客户端链，必须都从真实终局记录投影：原生PlayerMatchInfo终局通知，以及业务Settlement响应。`portable_match_end_values`仅pure codec，不创建终局。已核实BP_SOLPlayerState `bMatchOver h170 @+0xba8`、`MatchOverReason h171 @+0xba9`，4bit原生enum。`OnRep_PlayerMatchInfo 0xb576e80`核对owning PC后广播`DFMGameplayDelegates +0xb0`。Escaped=0、Dead=1、TimeOver=2、Quit=3、GiveUp=4等不是业务result enum。

业务`CSSettlementGetNewSettlementInfoRes`的65消息嵌套闭包已恢复，不等于完整DS上报所有schema；总报告仍记录两个未恢复map-entry类型。`SettlementServer.lua`hash`80bc6cefeb576b8f7d3b7199abe490bb91c80c9781de8c849cbb0a5909ee2322`：0.25(330–351)校验result与room；0.27(358–429)按GameFlow立即/延迟/补库存；0.29(441–519)按SNTF_SOL取数；0.40(632–639)请求带room且支持重连resend；0.71(1173–1195)要求match_info并解析mode/game_rule/season_change_info。`SettlementDataSOL 0.3`要求player.type及相应playing/end_game/quit_game子消息。默认Escaped=0绝不等于默认成功。

逃离结果还经`SettlementServer 0.42(680–709)`调用当前Pawn.PlayerExitComponent.PlayCutSceneBeforeSettlement。组件play`0xb258090`、sequence`0xb258aa0`；CacheCutSceneParams exec`0xd014c00`/impl`0xb203320`、88 native字节，但当前函数wire/layout未闭合。正常非视频失败路径`0xb258d2b -> 0xb20de80`也会广播完成委托，说明“不播放视频仍可完成等待”有真实分支，不意味着成功撤离。不得伪造完成delegate。

`SettlementLogic.lua`hash`d5206d013eda07b2f50a6e43317b2dfabef62c6b5c187bc6d1961fe74f8251ff`：0.29(670–682)由Game进入GameSettlement桥；0.48(1126–1216)清flag、SettlementEndBroadcast并等待离开/进入下一flow；0.50(1225–1257)重置重连、释放地图。`SettlementModule`hash`dccc7a79...`的0.23与0.60分别处理入口及ClearSettlement。服务器关闭连接不是travel已正确完成的证明。

独立SQL路径已经有`DurableWorldDispatcher.terminal` -> `DurableWorldSession.commit_terminal` -> 同SQLite事务`materialize_terminal` -> `match_over_result`，同room_id/room_seed另有wire-to-durable namespace映射。它要求terminal_allowed callback，但真实producer尚缺。一个证据SHA256只能标识记录，不能证明撤离/死亡条件；不能把客户端提供的retained_gids、奖励或“成功”直接传入。账号兼容与完整特征落库由主报告另行核查，本域不声明当前materializer已能无损处理全部新存档。

必须先冻结实际carry_in及当前carry_out、消耗/耐久/弹药/门卡/任务/曼德尔、终局原因和revision，在同事务真实落库并保存唯一result；然后才发native终局、EmptyNtf和可重复查询的业务响应。读取、重试、clear、delete_room_id与重连不重复提交。死亡/超时/主动退出/掉线必须独立terminal policy，不把所有退出当撤离。安全箱/保险/任务物保留必须明确源或本地规则。终局后旧世界命令全部拒绝，待发送delta可重放已提交结果但不能再改归属。

## 可执行接线顺序

1. 先核对当前trial frozen-source与观察器输入契约；保留旧拒绝，重新生产单独证据。闭合SubWorld/Level membership和本次PackageMap provider，不以旧manifest GUID代替当前映射。
2. 同admission建立世界authority：房间seed/config字节、任务、出口选择、有限物资与GID、静态/动态Actor身份、原点变换、锁/搜索/占用状态、服务器移动位置。Account读取、地图规则与库存不是三份独立“当前快照”。
3. 将真实permission/位置/provider接到dispatcher；修改installer的拒绝门槛必须带来源类型与失败测试。连接当前receipt ledger顺序分派PC226、Interactor71/72、Inventory45；不能旁路owner或initial-delivery门槛。
4. 首先打通一个实际保险箱的F聚焦、解锁、搜索、完整物品移动及原生结果；保持每条CmdGid、两侧revision与outbox。随后补全部物品操作，再扩散到普通门、卡门、password、地面pickup/drop和各额外交互。
5. 由实际世界状态产生高价值/任务/曼德尔/出口列表；补相应状态机和timer。候选筛选和world运行必须共用冻结结果；runtime_actor_resolved应由真实绑定推进。
6. 撤离/死亡authority生成terminal intent；先完成账号事务和immutable result，再投影PS170/171、过场及业务Settlement。最后验证Return/清房间/下一局与退出重开，不能先造结算页面当完成。

## 原生验收操作

下列是完成接线后的操作，不是本轮已执行测试。每次使用独立shadow、最长1800秒，启动前标明诊断或功能验证，结束核对SDK/INI/进程恢复。各地图/模式分别验收；一张图通过不勾销六图。

1. 记录admission、地图/模式、seed/config、原携带GID/数量/特征/任务。进图比对真实PC/Pawn/World、Actor映射、库存UI和本局标记。
2. 无卡/错卡/耐久零拒绝；真卡一次开门并消耗正确durability；关门、再次开、连续F/重传不重复扣。密码/破坏/电梯/索道/开关按实际地图分支分别操作。
3. 开真实箱，搜索中离开/重进，逐物显示与服务计时一致；取整堆后箱减少、背包增加，重复CmdGid不二次变化。拆分/堆叠/旋转/交换/装备/丢弃重拾覆盖全部已发布操作，总数量与每GID owner守恒。
4. 从真实事件生成曼德尔，携带/死亡掉落/再拾/解码中断/争夺/完成/带出与地图状态一致；地图任务完成与失败各一次，奖励在终局前后不重复。
5. 出口未开/负重/装备/付款条件不满足拒绝；满足时倒计时可见，走出取消，重新进入按规则恢复/重启；付费或水闸开关只扣/触发一次；死亡与倒计时同帧不能双终局。
6. 实际撤离 -> 原生match-over -> 真实过场/正常完成委托 -> Settlement -> 大厅 -> 退出重开；读取持久库存与carry_out逐GID/数量/特征一致。失败/死亡/超时/主动退出/断线至少各留一条明确处理记录。
7. 在“事务已提交但delta未ACK”“两侧delta已ACK但result未ACK”“账号已落库但EmptyNtf未送达”分别断线/重试。只重放同一结果；新连接代际不能继承旧lease发送资格，下一局不被旧世界/terminal污染。

本轮完成的是来源重新核查与接线/验收边界记录。没有新增原生玩法通过项，完整世界交互与真实结算仍未完成。

## 追加：六地图与所有玩法范围普查

本次追加只读重验原客户端完整SHA256与上述pin一致，并只扫描RVA`0x14d03000`、文件偏移`349185024`、尺寸`131049984`、flags`0x40000040`的只读数据节，SHA256为`1b7e580a9c4b8f15f5bfb416b55d4f758fe7944f43fe7cc8f1c37d5cb37b1a70`。下列RVA均为字符串位置，不是同名函数入口；`Server`和`_BS`名称不证明Net flags、参数布局、执行成功或服务端移植已完成。

### 六个真实地图族

以现有`DataTables/MapInfo.uasset/uexp`的162行完整解析为准，六个地图族原样命名为`Forrest`、`Dam_Iris`、`SpaceCenter`、`Brakkesh`、`Tide`、`AZ-5`。中文显示名未在本次闭合，不用记忆翻译覆盖原始名字。表报告的`source_table`误填了被引用的`MapInfoConfig_AZ-5`字符串，真实文件身份见source_uasset/uexp及哈希；它不是“162行都是AZ-5配置”。

- `Forrest`：MapInfo行偏移565，MapConfigMapID65，MapType9。资产注册表`MapQuestData_Forrest_Level1`偏移309555，MatchModeIdToDataTables键`141901103 / 141901201 / 141901203 / 2`。
- `Dam_Iris`：偏移817，MapConfigMapID67，MapType10。`MapQuestData_Dam_Iris_Level1`偏移307471，模式键`142201103 / 142201203 / 2`。只有其`2201 / Dam_Iris_Level1 / point_id1 / match_mode142201103`已由发布入口与原生选择关联；不要从模式数字拆出其它图的准入MapID。
- `SpaceCenter`：偏移1319，MapConfigMapID66，MapType16。`MapQuestData_SpaceCenter_Level1`偏移313723，模式键`143901111 / 143901113 / 143901201 / 143901203 / 2`。
- `Brakkesh`：偏移3123，MapConfigMapID83，MapType83。`MapQuestData_Brakkesh_Level1`偏移938837，模式键`148101101 / 148101103 / 148101201 / 148101203 / 2`。
- `Tide`：偏移18740，MapConfigMapID8809，MapType8809。`MapQuestData_Tide_Level1`偏移1221084，模式键`148801103 / 2`；总Tide行还有`148809103 / 148802113 / 148803123 / 1128821103 / 1148851243`等关联。
- `AZ-5`：偏移29181，MapConfigMapID890，MapType890。`MapQuestData_AZ-5_BigEvent`偏移2082496，模式键`148901103 / 148902113 / 1128921103 / 1128922103 / 1128923103 / 2`；BeforeBigEvent、BetweenBigEvent、ThermalPowerPlantEvent分别为独立资源注册，不能忽略为大坝事件换皮。

这些模式键来自`DataTableAssetInfo.MatchModeIdToDataTables`，证明按模式选择任务资源，不证明该模式当前开放、准入参数完整或`2`是可发布的真实战局模式。此处07:29Z普查时未找到的MapConfig/MatchModeDataConfig原表，已被末节08:26Z后直接PAK恢复推进：六图真实静态map/mode行现已取得。当前生效表重定向、服务端发布point_id、本局世界与出生/撤离的完整绑定仍未闭合。`DataTableAssetInfo`注册的DefaultPath为`/Game/DataTables/MatchModeDataConfig.MatchModeDataConfig`（偏移164005）及`/Game/DataTables/MapConfig.MapConfig`（偏移193615），原PAK实际表在`/Game/R13N/Common/Base/DataTables/`，须继续核对native DataTableManager的选择规则。其余五图GameplayConfig/出口/交互Actor未完成完整解析与原生操作验收。

### 模式不是一个SOL开关

三层模式定义分别保留，不互填ID：

- `GameModeConfig.uasset/uexp`四行：行1偏移71为SOL，下列`SOL_PMC / SOL_SCAV / SOL_SOL`；行2偏移972为PVE，`PVE_Easy / PVE_Normal / PVE_Diffcult / PVE_RealWar`；行3偏移2074为BigWorld及BW_LEVEL1..4；行4偏移3134为TDM及TDM_LEVEL1..5。这是实际配置声明，不证明每一分支仍开放或已能本地运行。
- 原生`EDFMGamePlayMode`，静态params RVA`0x1cd92230`，GS普通h84/4bit：None0、SOL1、Raid2、IrisDiscovery3、Conquest4、Breakthrough5、SafeHouse6、Intro7、BombDefusal8、GoldenGunGun9。名称保留源拼写；它不等于业务game_mode/sub_mode或上述EGameMainModeType。
- Trials已有原生`ETrialsMode`资源分支及地图51变体：Dam/SpaceCenter/Brakkesh/Tide的MapInfo分别为2251/3951/8151/8851；资产注册表任务模式键分别`1142251243 / 1143951243 / 1148151243 / 1148851243`。后续原表恢复已证实这些模式的`GameMode1 / GameRule14 / MatchSubMode24 / TeamMode3 / RaidID0`和各自MapConfig，仍没有发布point_id与原生验收。Forrest与AZ-5的同类Trials准入本次未闭合，不补造。

MapInfo还明确含MP/其它规则资源命名：Breakthrough、Conquest、TacticalConquest/TacticalConquestB、Siege、TeamDeathMatch、CaptureTheFlag、FlagWar/NavalFlagWar、SteelTorrent、HardPoint、FootBall、HVTAirCombat、Control、Hitter、BombDefusal，并有Night、Air、DynamicLayout变体。示例`IceLand_Breakthrough`偏移3637、`Cracked_CaptureTheFlag`16053、`Cracked_HardPoint`25721、`NavalBattle_NavalFlagWar`38323、`BombDefusal_Mansion`38592。`MatchServer.lua 0.60/0.104`另有BlackHawkDown、BlastGameMode、MusicFest等分支。不能据资源后缀推定队伍、计分、复活、胜负、载具或结算算法已实现；MP也不以SOL的提取战利品终局代替自己的规则。

### 额外玩法存在性与接入状态

下列分支均未形成当前生产玩法闭环。本次对生产`outputs/df-local-server/dfserver/*.py`搜索`Zipline|ZipLine|ShopStation|HeavyMachineGun|FixedWeapon|DoDrowningDamage|VehicleSeat|ServerEnterVehicle`无命中；这是该目录与表达式范围的检查，不能当作客户端没有这些功能。

- **载具**：原客户端存在`AGPVehicleBase::GetOn_BS`（RVA`0x164989d8`，文件偏移373915096）、GetOff、SeatForbidden/VehicleOwnInfo/ServerControlledState的OnRep；`UGPVehicleDataComponent::ServerGetOnCarWithSpecificSeat_Implementation_BS`位于`0x164c2470`（374085744）。已找到声明与诊断名；未恢复具体可用车型/地图生成、座位占用/上下车/控制权、运动碰撞、车载武器/弹药、车损死亡与乘客结果的服务器执行和receiver。
- **固定武器与重机枪**：`AInteractor_MachineGun`字符串`0x183b2918`（406527256），`UFixedWeaponSkeletalMeshComponent`、`FFixedWeaponFireDataRecord`及`OnRep_SkillFixedWeaponWhiteModelInfo`均存在。固定机枪、技能固定武器、建造固定武器可能不同分支；未闭合占用/角度限制/开火/装弹/伤害/离开/毁坏。普通携带枪的Modular初始化不能代表固定武器。
- **索道**：`AZiplineInteractorActor::OnEnterZiplineArea`字符串`0x15ef6058`（368006232），`UGPComBoardComponent::OnRep_ReceiveServerZiplineInfo`为`0x15dcf608`（366799368），`ReportZiplineInfoToServer_Implementation_BS`为`0x162751d0`（371672528）。存在上下索道、服务器报告、失败返回、冷却及移动模式声明；输入/RPC真Net标记与参数、当前索道Actor、轨迹/进度/退出与服务端移动权威未恢复。
- **电梯、开关、密码和破坏**：前文已有当前版本真实来源；追加又见`UInteractorGeneratePasswordComponent::OnRep_Password_ES`字符串`0x18280c70`（405274736）。密码不只是普通门open bit，电梯不只是位置teleport；每条分支需要自己的状态/验证/重放边界。当前只有普通门/三个箱体的有限候选，未覆盖各图所有实例。
- **环境危险**：`UGPComBoardComponent::DoDrowningDamage_BS`字符串`0x16262220`（371594784），`FGPLocomotionComponent::CheckFallDamage_BS`为`0x16550998`（374668696），`EDeadType::EkilledByPoisonGas`为`0x166c5058`（376194136）。这确认溺水、跌落伤害路径及毒气死因声明，未证明某地图已放置毒气区。具体危险volume、区域启闭/事件、伤害周期/抗性/死亡归因、同步与终局未接；不能把武器ElectricShock组件误当环境电击区域。辐射区等具体Actor/配置本次未资格确认。
- **局内商店**：`AInteractor_ShopStation::ValidateRequestPurchaseInfo_BS`字符串`0x17fd7c48`（402485320）、`OnRep_SellingIDArray_BS`为`0x17fd9b78`（402493304）、`USOLCurrencyInGameComponent::ServerBuyShopStationItem_Implementation_BS`为`0x18065b90`（403066768）、`UBasePlayerSettlementComponent::ServerSendShopStationBuyRecords_BS`为`0x182e5b90`（405688208）。已证实专门的局内购买与结算记录分支；不能用大厅CSMallBuy代替。尚需Actor/owner与RPC资格、售卖表/库存/限购/价格/局内货币、扣款和物品GID原子生成、空间不足/重复请求、售卖复制及终局记录。
- **其它事件**：AZ-5四阶段任务资源、Trials曼德尔、MP夺旗/据点/钢铁洪流/空战等源名已经说明当前单人大坝并非全部玩法。比赛目标、比分/阶段、复活、据点/旗帜归属、支援/建造、天气/昼夜及事件结果仍需按实际模式逐项闭合。本次未恢复的算法明确保留未知，不将名字、配置或静态Actor计为已接入。

这些分支进入总实施范围后，应各补“客户端输入 -> 真owner/RPC/字段 -> 服务器状态与计时 -> 复制/结果 -> HUD -> 持久化或模式终局”的独立契约，复用同admission/实例所有权/重传重连原则。具体功能未接之前，完整六地图/所有玩法的验收不能完成。

配套[结构化证据](../work/evidence/gameplay-world-research-20261020.json)保留新扫描的只读节身份、精确字符串位置和来源哈希；原始[MapInfo解析报告](../work/evidence/map-system-audit-20261018/native-mapinfo-actual-rows.json)、[模式配置报告](../work/evidence/map-system-audit-20261018/native-gamemodeconfig-actual-rows.json)、[模式到资源注册表](../work/evidence/map-system-audit-20261018/native-map-loading-asset-mappings.json)仍在只读peer目录。

## 追加：原始PAK准入表与世界资源恢复

### 方法与真实新契约

本次追加直接读取`DF_LOCAL_SOURCE_GAME/DeltaForce/Content/Paks`的257个PAK、1,174,183个目录项；全部主索引与二级索引SHA1校验通过。所选table/Lua的压缩载荷SHA1也通过；四张表均完整解析所有行到精确package trailer，再选行显示。Lua只解析字节码到精确EOF，不执行Lua。解密、解压及完整表仅驻留研究进程内存，stdout仅输出所选事实和来源，不打印/落盘密钥、不释放整包。原安装`oo2core_8_win64.dll`仅作为研究进程内的压缩codec使用（SHA256 `fc923f9bbbf185ca6e853de0e3ebbc81c839323e6e161cd0f75058c60a2b05a6`）；未加载游戏EXE或操作游戏进程。peer旧迁移路径在脚本内存中替换为原codec路径，未改peer配置。

新恢复的是实际字段连接，未从模式十进制数字拆MapID。六个代表模式的共同字段为`GameMode=1 / GameRule=4 / TeamMode=3 / RaidID=0`；MapConfig均指向`/Game/Maps/Iris_Entry/Iris_Entry`、`bStreamingLevel=true / bInGameLevel=true`，LevelName与SubWorldName一致。以下“偏移”是各自解压后uexp行起点，非PAK偏移或代码RVA：

- `Forrest`：`141901103`（MatchMode行偏移10176）-> `MapID1901 / MatchSubMode10` -> `Forrest_Level1`（MapConfig偏移65728）-> SubWorld偏移3987。MaxMatchDuration2100、DoorKeyConsumeMultiple1、bShowInMapSelection=false；MapType9，SOL规则，SOL子系统。
- `Dam_Iris`：`142201103`（13118）-> `2201 / sub10` -> `Dam_Iris_Level1`（71931）-> SubWorld2673。duration1800、门卡倍率1、show=true；MapType10，SOL规则，SOL子系统。它与既有已发布2201入口独立相互印证。
- `SpaceCenter`：`143901113`（16480）-> `3901 / sub11` -> `SpaceCenter_Level1`（77090）-> SubWorld5301。duration1800、门卡倍率2、show=false；MapType16，SOL规则，专属SOL_SpaceCenter子系统。不可复制大坝sub10/倍率1。
- `Brakkesh`：`148101103`（19422）-> `8101 / sub10` -> `Brakkesh_Level1`（82813）-> SubWorld10557。duration1800、门卡倍率1、show=true；MapType83，SOL规则，SOL子系统。
- `Tide`：`148801103`（92443）-> `8801 / sub10` -> `Tide_Level1`（232680）-> SubWorld21726。duration1800、门卡倍率1、show=true；MapType8809，实际GameRuleConfig是JailBreak，子系统也是JailBreak。业务GameRule4不能覆盖此世界规则差异。
- `AZ-5`：`148901103`（132732）-> `8901 / sub10` -> `AZ-5_Level1`（302796）-> SubWorld32238。duration1800、门卡倍率1、show=true；MapType890，实际GameRuleConfig和子系统均是AZ。

六行GameMode soft-class均为`/Game/BluePrints/GameModes/TestGame/BP_GameMode_PVPVE.BP_GameMode_PVPVE_C`。GameRuleConfig路径前缀为`/Game/BluePrints/GameModes/GameRule/`，真实对象分别是`BP_GameRuleSettingConfig_SOL.BP_GameRuleSettingConfig_SOL_C`、`BP_GameRuleSettingConfig_JailBreak.BP_GameRuleSettingConfig_JailBreak_C`、`BP_GameRuleSettingConfig_AZ.BP_GameRuleSettingConfig_AZ_C`。LevelSubsystemConfig从有界UAsset import链解出：-9为`BP_LevelSubsystems_SOL`，-10为`BP_LevelSubsystems_SOL_SpaceCenter`，-5为`BP_LevelSubsystems_JailBreak`，-2为`BP_LevelSubsystems_AZ`；完整路径及class保存在JSON，不能将不同子系统当同一个通用SOL实现。

Trials新增真实合同：`1142251243 -> 2251 / Dam_Iris_Level51`（mode/map行偏移129044/291027）、`1143951243 -> 3951 / SpaceCenter_Level51`（129856/292273）、`1148151243 -> 8151 / Brakkesh_Level51`（129467/291650）、`1148851243 -> 8851 / Tide_Level51`（130279/292902）。四行均`GameMode1 / GameRule14 / MatchSubMode24 / TeamMode3 / RaidID0`，MapConfig门卡倍率2，使用同Iris_Entry入口世界。这些仍只闭合静态表，未发布模式、未移植Trials运行状态机或终局。

### EntranceIdx与point_id的边界

WorldEntranceConfig的18行现已完整恢复，MapID字段实际为字符串。真实族入口包括`EntranceIdx1 -> "022"`、`2 -> "019"`、`12 -> "039"`、`14 -> "8802"`、`21 -> "8901"`，另有`67 -> "1921"`、`20 -> "3931"`。MapConfig实际行分别证实22是Dam_Iris、19是Forrest、39是SpaceCenter、8802是Tide_Level2、8901是AZ-5_Level1、1921是Forrest_Level21、3931是SpaceCenter_Level31。原表`EntranceIdx13 -> "076"`，但MapConfig76实际是`TestAIMap_Mobile`，且`bInGameLevel=false`；81才是Brakkesh。故不能猜13就是Brakkesh，也不能将入口14的Tide_Level2直接等同于模式148801103的Tide_Level1。

`GameModeServer.lua` SHA256 `c4ced93f1059d9cb8f91874a1d0084090d4263a95d443dcd7d9101548088e381`给出明确消费者：0.7（180–212）对WorldEntrance.MapID做tonumber并经MapConfig资格检查；0.8（214–231）装入MapConfig；0.140.0（2390–2407）成功响应后传入`response.board_info_array`；0.142（2424–2444）按sub_mode分派普通/night/flood；0.143（2446–2465）用`entry.point_id -> entry.mode.sub_mode -> entry.match_mode_type`保存整条entry；0.144（2468–2479）是night分支。0.33（510–574）检查某入口所存board条目的实际`entry.mode.map_id`，0.84（1059–1072）据此找入口。这里没有数字前缀匹配。`StrategicSelectionSOLMainPanel.lua` 0.21（192–369，SHA256 `0adc44e766147b3a05c70cc01b7ec1667d2e6c8777658e5fc472a2a994fdff3b`）按EntranceIdx请求模式。

所以本轮得到的是源表入口候选和确切mode/map合同。实际发布board对`point_id -> mode.map_id`的关联仍以服务器响应为准；现有独立观测只闭合大坝point1。Brakkesh的原表入口point仍未知；不能为了凑六入口使用13或新造数字。Forrest2、SpaceCenter12、Tide14、AZ-5 21可作为后续来源核查起点，不能直接标为当前已发布、已可进图。

### 原PAK位置、哈希与可核实替代范围

下列四表的原PAK、编码索引位置、物理载荷起点、解压后字节数、全部原始行的canonical JSON哈希均保存在配套JSON；canonical行hash是在解析soft-reference之前，对完整原始rows作sort_keys/ASCII/紧凑分隔符序列化得到。表原文件SHA256如下：

- chunk2，`DataTables/WorldEntranceConfig`：18行；uasset `d848221bd8ec47c4ffa2a81d44ba937f45b1338db69f07392863fd65c47c67af`，uexp `341458717d94d572004c8e3537a0e02870c3101cea652d8e9f0dc4176f110a63`。
- chunk2，`R13N/Common/Base/DataTables/MapConfig`：640行；uasset `e41784765610dfde36cbd23d99c37f26c42448af2f43b6482bb845da0459d372`，uexp `5486a2b773a5a387b8d835f2693be17ca4b21eebf1444282a0734cb110590221`。
- chunk2，`R13N/Common/Base/DataTables/MatchModeDataConfig`：424行；uasset `b1bddadb90cd7388415fb08bf2706341e819e9a5b05147c7d3eef2d6f1027492`，uexp `6845f7e0b45f47a313cdbe64818f167be03d14f9be2bcfc8dcda6798a42df883`。
- chunk73，`DataTables/SubWorld/DT_SubWorldConfig_Iris_Entry`：81行；uasset `78103cc76430791b6d40e19116d9878d16ba2f149049f246482b177bc965cfcf`，uexp `8f55c19e62c061f0427b172b32175dedd53b41bbbabccb2eea5ebd1deaf49199`。

全索引的精确Level1 GameplayConfig目录扫描只命中Dam（chunk84）和SpaceCenter（chunk91）；扩大到其它四地图族的同名GameplayConfig.umap后，另命中`Brakkesh_Level21`（chunk80）及`Forrest_Tutorial`（chunk83）。这只是原安装257个PAK的指定命名范围，未命中不表示没有该图资源，也未闭合动态子关卡、bin加载recipe或当前热更新资源。不能把有任务表/MapConfig当已找到所有箱体出口。

其中Brakkesh给出一个可核实的新替代范围：`1128121103 -> Map8121 / Brakkesh_Level21`，mode行87395/map行168010，`GameMode1 / GameRule12 / sub10 / TeamMode3 / RaidID0`；SubWorld行14499实际是`BP_GameRuleSettingConfig_Arena`和import -1的`BP_LevelSubsystems_Arena`。存在精确目录`../../../DeltaForce/Content/Maps/Brakkesh_Level21/GameplayConfig/Brakkesh_Level21_GameplayConfig.umap`，可以继续恢复这份真实Arena配置；不能把它替代Brakkesh_Level1的SOL配置或终局。

### 接线依赖与复现

`TableManager.lua` 0.18（237–267，SHA256 `f7cb43b6c7eb7c1cb0fa140f7471c9340d5149e2f6d70db9506d2579e81b4809`）在Lua缓存未命中后调用native `GetDataTableManager().GetDataTable(name)`。目前只闭合原始安装基线，不把实际发现的R13N表自动等同于当前运行有效表。下一步须恢复native DataTableManager的DefaultPath/R13N/overlay选取，再用已保存或后续获授权的board证据核对point/map/mode和世界加载recipe；六图自己的交互、出口、任务、事件、规则子系统与终局仍需分别接入。bShowInMapSelection不是业务开放证明，静态表duration/门卡倍率也须由当前模式覆盖规则解释后进入同admission快照。

只读[复现脚本](../work/research_world_admission_20261020.py)在本轮终局追加后SHA256为`c793a6c61ef264a7c673400ba82e81610f55ada9f42a70a263f559e2e77fa9c8`；08:33表恢复、09:17选表及10:12权威版本hash另存JSON。下例仅向stdout输出；也可用`--name WorldEntranceConfig`读取18行，或`--name GameModeServer --lua-terms point_id --lua-listing`查看真实Lua消费者。禁止将本轮原表恢复当成游戏运行测试。

```bash
PYTHONDONTWRITEBYTECODE=1 /c/Users/BaiGe/.conda/envs/python12_conda3/python work/research_world_admission_20261020.py --name MapConfig --name MatchModeDataConfig --name DT_SubWorldConfig_Iris_Entry --row '^(1901|2201|3901|8101|8801|8901|141901103|142201103|143901113|148101103|148801103|148901103|Forrest_Level1|Dam_Iris_Level1|SpaceCenter_Level1|Brakkesh_Level1|Tide_Level1|AZ-5_Level1)$'
```

## 追加：DefaultPath到R13N的原生选表规则

本次09:12:13Z追加复用了同客户端/同manifest的已有只读代码缓存，逐块校验后分析，没有采集进程。`ctf-reverse`仅用于静态字串、精确xref及pdata函数分析。全代码候选搜索每次校验349,562,443个已有函数字节；关键候选xref随后由所属pdata根和连续unwind片段的完整线性反汇编确认指令边界。这里恢复的是原生条件分支和原安装配置，不声明当前调用已执行或所有热修复分支都已闭合。

### 两张表自身的选择规则

直接重读原`DataTableAssetInfo`共2224行（精确trailer；uasset SHA256 `25c02646e684c7a9f939931d1f5802e32726d0013d16938938bb6c9b142b182a`，uexp `63b11be4de14db3fe78e075c6702d33779e2751f3a8bef45b20c275e6b7f9d83`），`MatchModeDataConfig`行偏移164005、`MapConfig`193615均为：`SyncLoad=true / UseScene2 / UseClientType1 / Category=Common / bPure=true / bDisableChunkRedirect=false`；`bReplaceDefaultPathWithMatchModeId=false`、`MatchModeIdToDataTables=[]`、`bCombineWithOtherTables=false`、`CombineWithThoseTables=[]`、`HasSubTableInDir=false`、`bEnableSQLite=false`。故这两表在原表声明中没有按战局模式替换整个DefaultPath或拼组合表，不能套用任务资源表的模式override规则。

`UDataTableSystemManagerLite::GetTableAsset`由真实缺行日志xref定位到`0xdd0a90`，范围701字节，SHA256 `29dcf6956bdf0d7b6114f7086617a5f6a4e7f8f34d7845625b8263ca7409a4a3`。它按表名在实际AssetInfo行映射查找；缺行返回null。`TableManager.lua`中的表名并非直接等于PAK磁盘路径。

### 原生重定向顺序

实际函数拼写为`UDataTableSystemManagerLite::ConvertRedictAssetPath`，pdata根`0xda6150`，连续范围986字节，SHA256 `0b3425d1d332d3450084e7b86decd8893098dc424b27705d5cd983a56d423ede`。重要边界如下：

1. `0xda61ce..0xda61e8`先以管理器`+0x2d2`处标志调用通用资源路径重定向`0xdf8a40`，然后才进入专属GameMode目录选择。后者由静态开关`0x1c9fe757`控制；本次没有读取它的运行时值。
2. 通用资源函数`0xdf8a40`，4208字节，SHA256 `662ac675cdaf7f341e3d51f4e0a125f1b77f131275f593556e63203fc7b005ce`，在`0xdf8d30`以`test al,8`检查传入标志mask`0x08`；该分支读取`AssetRedirects.RedirectedPackagePathsForR13N`，将匹配包前缀的路径交给R13N目录搜索。另有HD等分支，不能用mask`0x08`事实代替全部flag含义。
3. 原PAK chunk1中的`../../../DeltaForce/Config/DefaultEngine.ini`，物理偏移3293184、157191字节，SHA256 `e39c5d39c33bb86fef2376cbfeac438a6e5e802a043d05e689b4610ca93716f2`；行274–275明确`[AssetRedirects]`和`+RedirectedPackagePathsForR13N=/Game/DataTables/`。因此两张DefaultPath确实位于源配置的R13N匹配范围内。
4. 前缀构造`0xda2d80`，732字节，SHA256 `b2a6c1c1717e2edf9e71440f511fe1fbd3473f30153161fb69b382285fe1161a`，按顺序生成`/Game/R13N/{region}/{platform}/`、`/Game/R13N/{region}/Base/`、`/Game/R13N/Common/{platform}/`、`/Game/R13N/Common/Base/`。`region`取自EGameBuildRegion相关配置；platform可分PC/Mobile，本次不宣称当前字符串值已观察。
5. 搜索`0xdefc70`，621字节，SHA256 `5e5568e759916b4b10afca9cd3d1c22fc1dec49c50357eba2add99edfa9bdb03`：`0xdefe10..0xdefe6b`按数组顺序替换`/Game/`并调用存在性探测`0x10cc13f0`；首个命中在`0xdefec7`复制该folder返回，全部未命中返回空。调用者再形成完整包路径。这里不是按字母、文件时间或数值最大项选择表。
6. 其后`ConvertRedictAssetPath`按传入的引擎GameMode字节查`RedirectFolders`，以查到的目录替换`/Game/`，再次调用同存在性探测；只有命中才写回路径并返回true。目录缺失、配置null、目标不存在等分支返回false；调用前已有R13N改写的路径不能当作自动恢复到DefaultPath。引擎此处的GameMode字节不能未经来源核对直接填业务game_mode或GS枚举。

原`DefaultDatatableConfig.ini`物理偏移3283898、1026字节，SHA256 `1d26ec872ae2ce8d94fd062147437e534e5af7cd20c97254df8e7c3ef2cd8857`。行1–2为`/Script/GameCore.DatatableRedirectPathsSettings`，明确SOL -> `/Game/RedirectDataTables/SOL/`、BattleField -> `/Game/RedirectDataTables/MP/`、BP -> `/Game/RedirectDataTables/BP/`、JQQ -> `/Game/RedirectDataTables/JQQ/`；行4–5另给GameMode到InGame use-scene映射。它和通用R13N是先后两层规则，不能合并成“SOL总读一个目录”。

### 基线结论与热挂载边界

257个原PAK的全目录中，两表同名uasset各仅一个，均为已恢复的`R13N/Common/Base/DataTables/`资产，没有地区/平台优先项或上述专属目录的同名竞争表。因此可确认：**在已恢复的正常R13N分支和原安装配置下，上轮六图mode/map表是有原生加载规则支撑的基线来源。**这推进了“为何DefaultPath指向DataTables而实际文件在R13N”的具体未知；不能升级为当前客户端已加载该hash的实证。

热挂载是实际分支：`UDataTableSystemManagerLite::OnPakFileMounted` pdata根`0xddea90`，3391字节，SHA256 `a7fc7d389de28b0ba8462f0d6c7df663e9b01855d6b7a216ff7689ec61961018`。真实mount/reloaded日志位于其指令边界，`0xddf1c4..0xddf1d4`取管理器`+0x2d0`处GameMode再调用ConvertRedictAssetPath。故已有缓存表可能在挂包后改变，Lua缓存、native引用、批次及当前mounted packages仍需一致；本次未恢复全部替换/清缓存时序，也未扫描原安装范围以外的shadow热更新。

接入时应将两表实际来源路径/hash、AssetInfo规则、region/platform、重定向标志和实际挂载代际纳入同admission配置资格。当前仍欠管理器`+0x2d2`标志的运行时来源资格、开关实值、完整挂载优先级与实际当前表内容。不能为了宣称六图有效而删除这些门槛；同样不能因为未做运行时验证就否定本轮已恢复的基线路径合同。世界坐标、PackageMap与permission仍是另外的生产者依赖，静态表/relative_location不提供距离权威。

复现原生规则可用`--native-function 0xda6328 --native-function 0xda2f6b --native-function 0xdefd80 --native-function 0xdf8e8c --native-function 0xddf1d4`；原配置用`--name DefaultDatatableConfig --text-pattern '.*'`及`--name DefaultEngine --text-pattern 'AssetRedirects|RedirectedPackagePathsForR13N'`。Git Bash向native-literal传`/Game/...`时设置`MSYS_NO_PATHCONV=1`，避免shell把字面资产路径改成宿主磁盘路径。

## 追加：真实门卡与撤离权威函数

2026-10-20 10:06:43Z整理。本轮仅从原EXE不可变数据和既有`native-code-cache/1792259162856698600`恢复函数，未访问进程、启动游戏、发包或访问DB。EXE和manifest沿用本文固定hash；`.rdata`范围RVA `0x14d03000`、131049984字节的SHA256为`1b7e580a9c4b8f15f5bfb416b55d4f758fe7944f43fe7cc8f1c37d5cb37b1a70`。配套JSON的`native_world_authority_recovery`记录每个pdata根、连续unwind范围hash、关键指令、只读来源与复现参数。线性解码覆盖这些范围，未声称整个DS或全部热修复分支已恢复。

### 71/72确实落到哪个实现

`SOLInteractor`真实构造函数`0xffc4050`在`0xffc407e/85`装入primary vtable `0x1a67fe40`。71的exec `0xcec12e0`在`0xcec13f9`调用virtual+`0x760`，只读槽值实际是`0xbbe60e0 ServerExecuteInteractByTag_Implementation`；72的exec `0xcec1560`在`0xcec160d`调用virtual+`0x798`，槽值实际是`0xbbe8c70 ServerInteractAction_Implementation`。这次以构造函数写表和实际槽值确认继承后的处理器，未只凭UHT函数名猜实现。

71先检查有效owner/world，再于`0xbbe6fa5`调用`DSCheckCurrentInteracting 0xbb2b7d0`；失败不会继续dispatch。成功后`0xbbe70f2`调用virtual+`0x8c8`，实际槽值`0xbbdfd10 ServerDoExecuteInteractByTag`。该函数检查world，通过`0xbefcea0`按tag找executor；有效executor分支和缺executor的interface分支各自存在，后者在`0xbbe0f5c`调用target-interface+`0x148`，随后self+`0x900`。72也通过target-interface+`0x148`和self+`0x900`，并非一个可直接代替71全部资格检查的“开门成功”入口。executor到具体process的完整调度及所有条件enum映射仍未闭合。

`DSCheckCurrentInteracting`按顺序检查：PlayerState、CurrentCanOperate、PlayerInInteractorRange、PlayerPassFilterCollision、InteractorCanOverlap、ItemOwnProtect、CaptureSafeBox、UnlockSICSafeBox、DoorOnlyServer、InterlayerOpenBox、RebornInterlayerOpenBox、OwnerIsSelf；每项false有拒绝路径。`DSCheckPlayerState 0xbb402a0`实际查询target+`0x4d0`，并检查owner/PlayerState状态，包括PS+`0xba8`的MatchOver；角色及终局资格不能略过，死亡/倒地各状态的全部特殊分支尚未恢复。`DSCheckCurrentCanOperate 0xbb2a980`查询target-component+`0x4d8`。这些目标动态类的具体override还须按每种门箱绑定，不能统一返回true。

`DSCheckPlayerInInteractorRange 0xbb38830`不是一个常数距离：它处理运行时编码位置后调用target-component的filter虚函数+`0x658`和+`0x7d0`，false走明确拒绝路径。具体目标类filter算法及运行时EncVector资格仍缺。`DSCheckDoorOnlyServer 0xbb2db80`则在有效DoorBase和有效owner下，owner+`0xd59`、door+`0x1611`、door+`0x1612`均非零时返回false；这三字段的正式UHT命名未恢复，保持原偏移，不猜含义。三个SafeBox磁盘relative_location、null attach_parent和root export 236/238/274均不能替代这里所需的运行时位置、碰撞及动态目标身份。

### 门卡条件与真正扣除

原`BP_Interactor_RotateDoorBase` ReleaseLock process export35明确有`AcquireTags=Interactor.CheckCollision.Switcher.Close`（uexp22591）、`MustConditions.CompName=InteractorOptConsumeItemExecute`和`OptCondition_ConsumeItem`（22636）、`TriggerTag=Interactor.CheckCollision.Door.ReleaseLock`（22501）、`bCheckServerCurrentCanOperate=true`（23126）。ExecuteNameChains（22804）分三组：空手；解锁动画及spawn mesh；取回武器、锁switcher、spawn mesh及consume。**consume是前置资格条件，但实际扣除在最后执行组。**不能把数组内顺序当已证明的跨组件事务、失败回滚或动画完成时点。

实际consume类由StaticClass getter`0xcf9d090`的构造thunk`0xcf9e4e0`指向ctor`0xbc37290`，ctor写primary vtable `0x17bc24a0`；其+`0x490`确实指向`0xbc97880 ServerDoExecute_Implementation`。后者检查有效DoorBase：door+`0x15c0`非零且three-colors-state+`0x154c`等于3时跳过扣除；否则调用`0xbc52c70 DoConsume`。这些字段还需和每个实例配置/动态状态关联，不能用统一免费门规则覆盖。

已恢复的资格实现为`CheckExistCover 0xbc40d60`、`DoCheckExistCover 0xbc50b70`与GID分支`0xbc50d80`。BS原生hook记录分别`0x1d0c2f80`（ID `0x8c73`、名称指针`0x182eff78`）及`0x1d0c2f00`（ID `0x8c6b`、指针`0x182ee720`）；候选hook必须再以函数指令边界和本类字串确认，因为别的热修复命名空间有同数字ID。实际helper`0xbb7db80`从目标InteractorInterface+`0x648`按配置名取组件，强制cast为consume类，再调用CheckExistCover；此helper到全部process条件enum的上游映射仍未完全证明。

CheckExistCover先检查本组件ConsumeInfo.IsNeedConsume，尝试master-key候选，再试普通候选；type-byte2走GID分支。DoCheckExistCover从传入角色取得有效背包，逐条验证20字节consume条目，同item身份的数量/耐久累计分别经`0xbf6a1f0/0xbf6ad30`，回调`0xbf53890/0xbf538f0`确认累加实际实例count和durability。单条资格`0xbe8eb00`明确是 **(required_count>0且total_count>=required_count) 或 (required_durability>0且total_durability>=required_durability)**，候选条目之间也是任一满足即可。GID资格分支则枚举指定实例、核对item身份并比较该实例durability；本轮未将所有类型语义及绑定限制恢复完毕。无效背包和没有合格条目正常返回false。

实际扣除`DoConsumeByArray 0xbc53030`从GameState+`0x774`取地图倍率，`0xbc53327`引用原生日志`DFMGameState->MapConfig.DoorKeyConsumeMultiple`确认字段用途。初始化倍率1是找不到合格GameState时的原生局部分支，不是本地可用默认准入合同。数量分支调用`0xbf4c350 AttemptConsumeItemByID`；耐久分支将条目+`0xc`乘地图倍率（`0xbc53650`），按路径调用`0xbf4c9a0` ByGID或`0xbf4c9b0` ByID。上面的普通资格helper只比较原条目，未在其已恢复范围乘倍率；不能合并成一个自创公式，倍率后不足的实际Attempt行为还需恢复。GID消费另有`0xbc53b70`，不能只移植whole-stack数量。`InitConsumeItemInfoFromOwner 0xbc73990`从有效门owner+`0x1570`比较/复制到组件+`0x170`，不是接受客户端自报要扣的物品。执行体可见Attempt调用后的记录和SubmitDoorOpenInfo，但未证明扣除结果与锁切换有原子回滚；本地必须实现同实例扣除、重传幂等、失败不变与数量/耐久守恒，再联动状态复制。

### 付费出口、计时完成与状态转移

`UExitCheckerPayment::TryPayment 0xc43a7e0`从有效角色+`0x3bf8`取局内货币组件，从exitActor+`0x474`取价格；`0xb2d4450`比较price与wallet+`0x108`，不足立即false；足够才调用`0xb3113d0`。后者以consume参数调用`0xb457580 ServerAddOrConsumeCurrency`，该函数在服务端路径再次比较余额，`0xb4577a5/a9`执行`subss`并写回wallet+`0x108`，然后更新持有物/通知。它不是大厅余额、图标或ACK。重复进入是否已付费、多人共享/逐人支付以及重连恢复仍须继续恢复入口checker状态，不得每次重传都扣。

`APlayerExitBase::OnCountDownOver 0xc40bbf0`真实存在单人/列表分支并检查角色，通过`TrySetCharacterExitState 0xc43aa20`推进；后者有明确NotDS拒绝，还含配额、角色和组件资格。`ProcessCharacterEscaped 0xc41eb50`调用`UPlayerExitComponent::SetExitState 0xb26cf70`，true后调用的`0xc3ec1a0`本轮进一步确认只是`CheckHostageEvacuation`；普通终局广播来自SetExitState内部的OnStateChange分支，详见后续追加。计时器建立、离开区域取消、死亡/掉线取消、重新进入及不同exit子类完整规则尚未闭合；不能单独调用完成callback表示计时自然结束。

SetExitState先检查有效PS/owner和owner role+`0x130 == 3`（失败日志HasAuthority=false），拒绝已Escaped和同状态，再查真实转移表。原enum只读记录`0x18782850`和initializer`0xb22a630`闭合：Normal1 -> WaitingToEscape2或Escaped3；WaitingToEscape2 -> Normal1、InEscaping5、Escaped3、ReadyToStartEscape4；ReadyToStartEscape4 -> Normal1或WaitingToEscape2；InEscaping5 -> Escaped3。Escaped3没有后继。initializer以有界byte区间交`0x59165b0`建集合，后者确实逐字节插入；此处不是猜枚举编号。

成功转移把exitActor写入PS+`0xf08`，调用`ADFMPlayerState::SetExitState 0xb597ef0`，其自身再检查authority并把新state写PS+`0xf10`；component随后执行状态回调。**PS ExitState并不等于PS+0xba8 MatchOver，更不等于业务保存。**本轮未恢复从所有逃出/死亡/失败/退出路径生产完整immutable terminal receipt并驱动结果载荷、PS170/171和账号事务的完整调用链；local terminalauthority消费者仍缺生产者，不能独立假成功结算。

### 实施与验收依赖

可执行顺序是：同admission锁定实际模式/表来源/地图倍率和初始带入实例；资格合格的PackageMap映射把71/72的owner/target/component/tag/context接到具体原类；恢复目标CurrentCanOperate与collision/range及consume条件；以事务保存实际GID/count/durability扣除与门状态，失败/重传同结果；服务端clock驱动每个exit checker/payment/倒计时/取消和上述状态机；由真实逃出或死亡等terminal原因冻结carry/丢失/安全箱/任务事件，最后让唯一receipt、结果复制与账号落库共用提交结果。各步来源和失败路径均要保留，不能先ACK再声称原生玩法已执行。

获授权的原生验收应分别覆盖无卡/错误卡/数量不足/耐久不足、地图倍率、GID与普通卡、倒计时跳过消费分支、同请求重传和并发开门；付费余额不足/刚好足够/重复进入、离开区域/死亡/掉线/重连取消、非法及重复状态迁移、成功撤离后再交互拒绝。每例要对照门/背包/钱包/计时/terminal receipt/PS及重开后的账号实例，不用按钮动效或结算页截图代替持久化断言。SOL的这些base路径不能直接泛化为MP/Trials、Arena/JailBreak/AZ或六图全部出口、AI死亡与世界事件；这些分支仍按前文范围分别接线。

本轮收尾另重读协作者的最新源码：membership `_read_trial`49–60已允许精确public `outputs/native-account-provider/client-observation.json`，GUID `_read_trial`89–100已允许该输出目录；`portable_gameplay_observers`212–237确实顺序调这两观察器，并保留profile/source冻结检查。因此早先path拒绝是历史问题。新出现的trial `1792490092599202600`已有membership报告（hash `b0d46a57de7103efdab790ee0411a61d0acb6e9e7c9e0224d8ca9be8e50462f2`）拒绝`object_slot_changed_during_metadata_read`，GUID报告（`cd9518f47c911c7cf7cf69c3c213e596cab4074776aa64dc7b7367d64fc725e9`）拒绝owned image/trial/profile/source seal changed；报告本身没有内嵌时间。此处只记录已有文件，未触发观察。两项均没有补齐当前权威绑定或证明本轮门卡/撤离已执行。

## 追加：死亡撤离到终局与远端结算边界

本轮10:40:18Z前完成静态追踪，仍使用同EXE、同既有cache，未刷新上述两条失败观测、访问进程、启动游戏、发包或访问DB。新证据见JSON `native_terminal_bridge_recovery`；本节比日志同名更严格地以真实类getter、构造写虚表和槽值识别消费者。

**撤离广播已闭合到延迟终局入口。** `SetExitState -> OnStateChange 0xb24f960`在新状态Escaped时调用`0xb24cd20 OnPlayerExitPointEscapedTimerHandle`。它清理组件timer handle+`0x120`，校验owner角色和PlayerState，将PS+`0x4c8`设1；经`0x73fee20`取得GameplayDelegates后先广播+`0x170`的角色/controller事件。仅组件+`0x108`非零时，才向同对象+`0x5f8`广播reason0和PS+`0x498`的UIN（`0xb24cf16`清零edx，`0xb24cf1b`调用delegate+50）。不能省略这一条件，也不能把+170的统计/事件广播当作MatchOver。

`UDFMSettlementComponent::BeginPlay 0xb810b10`在`0xb810c95`建立callback thunk `0xb298190`，于`0xb810ceb/cfd`绑定GameplayDelegates+`0x5f8`。此9字节thunk确实跳virtual+`0x418`；SOL真实虚表该槽是`0xb83d110 OnDelayServerGameEnd`。后者`0xb83d1ec`检查DS资格，false走明确blocked because not on DS并退出；它构造捕获self/reason/UIN的timer delegate，callback thunk `0x3998548`确实跳virtual+`0x410`，经`0x13060eb0`交TimerManager。SOL该槽是`0xb84fa90 OnServerGameEnd`。本轮闭合了callback目标，未声称所有timer delay/取消/重入时序已恢复或执行。

**死亡不能简单用HP为零直接结算。** 实际`OnPlayerDied 0xb843f30`含Controller、AIDebug、击倒/击杀者、AI无infocard、观战超时等分支；不是只有一个Dead常量。`OnPlayerEndDeathWatch 0xb844ff0`再次验证Controller及GameState：GS+`0x6e1==2`的Raid分支检查同伴，仍有存活队友时广播reason3；全灭分支会等待其自己的终局处理。其它分支在`0xb8451f5`检查PS+`0x4b4`，非零广播reason1，零广播reason3，均带真实PS UIN到GameplayDelegates+`0x5f8`。此处保留偏移与已恢复分支，不把所有倒地、死亡、结束观战、退出及复活状态合并。

**SOL实际终局槽有可证明缺口。** `/Script/SOL.SOLSettlementComponent` StaticClass getter `0x104d6950`把constructor `0x104d7bf0`交给UClass；constructor先调用base `0xb804c50`，在`0x104d7c0a/11`写入primary vtable `0x1a8f6428`。该表+410/418分别是上述OnServerGameEnd/OnDelayServerGameEnd，+`0x440`却是`0xb845590`。OnServerGameEnd枚举和筛选PS、区分reason及目标UIN，并在`0xb850001`等位置调用此+440。`0xb845590`的263字节连续函数体正常路径只有hotpatch入口/出口处理（ID `0x65af/0x6569`等）后return，没有正常的SetPlayerMatchOver、玩家数据构建或发送调用。因此这份**安装客户端的该原生SOL槽**不能提供一条无条件完整终局producer；当前有效hotpatch绑定、Blueprint额外消费者或官方DS构建是否另有实现仍未知。本结论来自实际函数体，不是搜索不到某字串就断言整个客户端不存在逻辑。

有一个明确反例：完整`0xfe09ef0`虽记录`UDFMSettlementComponent::OnPlayerMatchOver`日志，并调用PS setter和DSLogic，实际constructor `0xfe6ba10`所写虚表`0x1a61c380`来自getter `0xfe69e40`，后者明确是`/Script/PropHunt.PropHuntSettlementComponent`。本轮将其作为排除证据，不挪为SOL producer。SOL绑定另经character协作者以原数据独立重验一致。

**实际SOL玩家组件有另一条数据发送链。** `/Script/SOL.SOLPlayerSettlementComponent` getter `0x104d3a80 -> ctor 0x104d4240 -> primary vtable 0x1a8f24f0`。其base Player ctor `0xb292b80`在`0xb292c27`构造内嵌`pb.SettlementNtf`；真实+`0x470`槽是`0xb45a7e0`，含PlayerInfo初始化资格、already settlement拒绝、reason合法性、死亡/已撤离的ExactlyLeave处理、物品/统计收集。它在`0xb45b47e/488`把组件+`0x5d8`交`0xae8f380 ServerSendSettlementData`，之后在`0xb45b6a9`设置PS+`0xe84`的已结算标志。Base ServerQuitGame_Implementation `0xae861f0`先拒绝已结算，再依次调用该+470、`0xae7e7f0`、+478、+450以及有条件的+448、+458；不能将这些带前置状态的内部函数直接作为任意客户端结算命令。

ServerSendSettlementData校验GameState和bot条件，普通真人路径在`0xae8f7c1`调`0xae845a0 SendSettlementInfo`；GameState+`0x6e1==8`等分支另处理，不泛化全部模式。SendSettlementInfo要求有效GameMode及DSLogic，`0xae848d4`调用`0xb7f0c10 UDFMDSLogic::SendSettlementInfo`。原生getter `0x6a944a0`返回该消息type name `pb.SettlementNtf`；发送器在`0xb7f0d3d`调用传输辅助`0x2f94290`，参数中确有目的`settlementsvr`和方法`SSSettlement`。这条真实发送链可恢复；它与上述SOL+440终局入口的完整交汇尚未闭合。

**DS报告与业务结果不是同一份奖励清单。** 原chunk1的`ds_common_editor_pb.lua`本轮重新解压校验SHA1、解析到准确EOF：物理32858112、509377字节、SHA256 `5fe89634d480907ba0f4657ef699151e147594750ddba37247a50d718ac8b753`。`SettlementNtf` decoder/encoder 0.52/0.53（943–995/997–1041）给出player_id#1、match_info#2/DsMatchInfoNew、team_info#3/DsTeamInfo、status_array#4/DsPlayerGameStatus[]、ds_never_connection#28等；原native protobuf type name和传参确认发送对象，未声称已核对每个C++成员偏移与每个Lua wire字段。尤其`DsQuitGamePlayerStatus.final_props#13`和业务响应`GspQuitGamePlayerStatus.carry_out_props#13`名字、含义及生产阶段不同。死亡后的final_props不能直接当账号应返还物品；必须经真实终局reason、安全箱、丢失、任务/事件及服务器实例规则投影。

PS终局复制的setter也已找到：`ADFMPlayerState::SetPlayerMatchOver 0xb599ed0`在`0xb599f54`写reason到+`0xba9`，`0xb599fca`写MatchOver到+`0xba8`，更新生存时间，并在特定netmode调用`0xb576e80 OnRep_PlayerMatchInfo`。OnRep消费已终局字段并通知客户端delegate；这个setter不是携带库存、规则和账号资格的原始authority。Lua仍需先收到真实业务结果，验证room/result和对应status子消息，再处理cutscene/flow；不能只复制170/171就生成成功业务结果。

**账号写入边界保持未知。** 这里证明的官方边界是native报告交给远端`settlementsvr/SSSettlement`，以及此前已恢复的客户端EmptyNtf/fetch结果消费者。远端如何校验报告、决定carry_out、写账号、生成可重试结果及发布通知的服务源码，本轮没有得到；不以此断言安装客户端全部代码都不含任何其它writer。local自己的immutable terminal/SQL/outbox是待接的实现，不是上述原生发送器等价物。必须补齐真实SOL authority producer和唯一terminal identity，原子提交带入/带出/丢失/条件/任务变化，再从同一结果投影PS与业务响应；发送报告、收到ACK、展示结算页和写一个独立成功receipt均不能替代这一步。本轮未进行原生终局或落库验收。
