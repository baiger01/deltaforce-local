# 本地战局运行能力调研

调研日期：2026-10-05，后续核查至 2026-10-06。结论依据为安装文件、已校验 Lua、原生运行时代码，以及本机安全屋、靶场和大坝诊断日志。

## 结论

已实测安全屋角色绑定，以及靶场的射击伤害、靶子倒地和复活。客户端确实保留可运行的本地玩法能力，但目前不能证明零号大坝完整战局可以由零售客户端独立运行。

本机安装目录未找到独立游戏服务端、编辑器或游戏工程文件。尚未核实到可复用的同版本服务端组件；这不等于证明其他来源不存在这些组件。

已确认客户端保留真实的 GameMode 工厂、控制器创建、角色创建与控制器绑定实现。已读取 `ADFMGameMode::InitOfflineController`、`InitOfflineCharacter`、`SpawnPlayerController` 的实际函数体，并串到 `SpawnActor`、`FindPlayerStart`、`SpawnDefaultPawnFor` 和 `Possess`。离线控制器类为 `DFMOfflinePlayerController`，类元数据的父类引用指向原版 `PlayerController`。这些入口没有单独证明本地输入已经绑定，也尚未证明可建立大坝战局。当前大坝资源加载后仍没有完成玩家控制器与角色绑定；随机出生、高价值标记也没有恢复。

大坝两个主地图包的实际属性已恢复：`PersistentLevel.WorldSettings` 指向 `DFMWorldSettings`，其中保存的 `DefaultGameMode` 是 `BP_GameMode_PVPVE_C`。同包另一对象引用的 `BP_Test_GameMode_C` 未被该 Level 选中。这是静态地图默认配置；尚未证明运行时是否受到 URL 参数覆盖，也没有取得 PVPVE 蓝图的 PlayerController/Pawn 类默认值。

进一步确认了原生 `InitGame → InitDSLogic` 对象创建路径，以及 `pb.Any2DsSyncPlayerInfoReq → DsPlayerInfo` 的新增、更新和登录查询链。这里有实际函数体和本机协议源文件证据，仍没有观察到大坝的权威世界实例、资料表实例或本地输入绑定。当前应继续核实这条原生路线的启动条件；不能将已有 Python 控制握手当作这套原生战局初始化已经完成。

本机失败试验的归档报告进一步确认：端口 `61908` 对应的一轮试验累计观察到 2 次 Join，但配置的地图 Actor profile、发送的初始 Actor 和 ACK 数量均为 0。该轮没有进入初始 Actor 发送阶段。这不能解释旧机器已创建 Actor 后仍绑定失败的另一轮试验，也不能证明源码缺少 Actor 发送机制。

连接类的玩家关联调用也已读取：`UGPNetConnection` 虚表 `+0x2c0` 指向 `HandleClientPlayer`，通过门控后调用基础绑定函数。门控构造时检查字节的初值为 0，会放行基础绑定；不能直接归因于无缝切换门控。现有本机元数据报告仍不能提供完整的 PlayerController、GameState 模板和复制属性布局，初始 Actor 发送是当前更早的实测缺口。

## 核查范围

- 安装目录：`DF_LOCAL_SOURCE_GAME`。
- 安装配置：`WeGameVersionStr=1.101.37117.36.8`，`GameResVersionStr=1.101.37117.36.33`。
- Shipping SHA-256：`4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。
- 对已有索引内的 5,707 份 Lua 逐份解析并核对源哈希，成功 5,707，失败 0，共 77,286,588 字节。这是索引覆盖范围，不能等同于所有原生代码或 Blueprint。
- 文件检索覆盖安装目录内的 EXE、DLL、Linux 二进制、编辑器名称、`.uproject`、`*Target.cs` 和模块描述；未找到独立游戏服务端或工程。`VersionServerConfig.xml` 是启动器版本更新配置。

## 已找到的调用链

下表的源文件均来自安装包 `DeltaForce/Content/Paks/pak-0-0-pakchunk1-WindowsClient.pak`。函数编号和序列化偏移来自 Lua 解析结果，源哈希保留在对应证据文件中。

| 来源与定位 | 已核实内容 | 适用边界 |
| --- | --- | --- |
| `RangeLogic.lua`，PAK entry `25354240`，函数 `0.26`，偏移 `20925`，源行 527–681 | 获取本地 PlayerController，调用 `SpawnDefaultCharacter`，加载靶场，进入靶场阶段并初始化角色、武器和装备；本轮已实测角色绑定及射击、伤害、靶子复活 | 依赖已有本地控制器；不能据此认定能创建零号大坝的初始控制器或战局，移动操作还未取得单独确认 |
| `IrisSafeHouseSubStageLogic.lua`，entry `21592064`，函数 `0.4`，偏移 `7807` | 获取本地控制器，创建默认角色，传送至安全屋默认位置 | 属于安全屋流程 |
| `EnterIrisWorldLogic.lua`，entry `21518336`，函数 `0.1`，偏移 `794` | 构造 `-game -server` 命令并连接本机；`StartLocalDS` 调用受 `_WITH_EDITOR` 条件限制 | 该调用点明确依赖编辑器条件，不能直接作为零售客户端本地开局入口 |
| `MatchServer.lua`，entry `34736128`，函数 `0.62`，偏移 `42931` | `_OnCSLobbyLaunchLocalDsNtf` 获取工程路径，构造含 ROOM_ID、DSA 和 GameMode 参数的命令，调用 `UGPGameplayStatics.StartLocalDS` 与 `UDFMIrisEnterSeamlessGameplayHelper.StartLaunchLocalDS`；所属 Lua upvalue 已重新核对 | 保留了调用流程；同名原生入口不能混用，命令构造和返回成功不能单独证明服务端已随客户端提供 |
| `MatchServer.lua`，函数 `0.65`，偏移 `46896`，源行 1092–1123；函数 `0.66`，偏移 `48289`，源行 1126–1176 | 离开安全屋时设置客户端无缝切换并打开 `Iris_Entry`；进入安全屋时使用通知中的 DS 地址、端口与令牌构造 URL 后打开地图 | 属于安全屋进入和返回流程；这里未见创建初始 GameMode 或控制器的实现 |
| `PSOAutomation.lua`，entry `35481600`，函数 `0.1`，偏移 `571` | 工程路径、本地 DS 启动、本机地址连接 | 自动化测试入口，完整运行条件未核实 |
| `MatchServer.lua`，函数 `0.147`，偏移 `143750` | `Forrest_Tutorial` 使用原生无缝进入辅助流程 | 教学入口存在；是否能脱离战局服务独立运行尚未证实 |

`IrisSafeHouseEventLogic.lua` 中的 `Possess` 位于安全屋低内存清理流程，用于控制备用 Pawn 并清理旧角色；不能把它解释为地图战局的角色绑定实现。已有日志中 `isStandalone:1` 的角色记录发生在大厅进入准备阶段，也不能证明大坝已独立运行。

## 四种模式的本地内容

用户截图中的四种模式均有本地客户端入口代码。未找到独立服务端不能解释为这些模式的地图、模型、界面或客户端逻辑全部缺失；各模式资源是否安装齐全需要分别核实。

| 模式 | 本轮确认存在的内容 | 尚未证明的能力 |
| --- | --- | --- |
| 烽火地带 | 模式切换、匹配与地图进入代码；前轮已经读取大坝地图的出生及物资配置，客户端实测也走到了资源加载完成 | 地图战局的控制器与角色创建、绑定，以及完整玩法运行 |
| 全面战场 | `GameModeConfig.lua` 中的 MP 模式切换，以及 `MatchServer.lua` 中的 `GameScene_BattleField` 入局分支 | 独立本地战局运行；本轮未核实该模式全部地图资源是否齐全 |
| 黑潮爆破 | `LobbyBlastingEntryLogic.lua` 的地图选择逻辑和 `MatchServer_Blasting.lua` 的选干员、入局确认请求 | 完整本地爆破战局运行 |
| 黑鹰坠落 | 章节与“孤军奋战”选项、单人开局请求、独立 BHD/UE5 程序启动与 DLC 检查 | 当前机器上的完整战役扩展包位置、实际单人运行，以及是否可复用到大坝 |

黑鹰坠落的 `BHDStartGameLogic.lua` 位于 PAK entry `22974464`。函数 `0.1`、偏移 `1970`、源行 43–53 设置 `SingleStart` 并打开章节选择；函数 `0.3`、偏移 `3710`、源行 86–116 调用 `ReqSingleBeginMatch`。`BHDServer.lua` 函数 `0.28`、偏移 `12290` 发出 `CSBhdSingleBeginMatchReq`，成功回调进入 `MatchServer:StartMatching`。因此，单人选项不能直接等同于无需服务的离线运行。

`LobbyBHDEventLogic.lua` 函数 `0.11`、偏移 `12204` 通过 `GetReleaseBHDPath` 或测试路径调用 `LaunchUE5`。`BHDHelperTool.lua` 函数 `0.1`、偏移 `1398` 使用 DLC 安装目录接口；函数 `0.0` 和 `0.2` 还包含 `BlackHawkDown/version.json`、`BlackHawkDown/` 路径。`BHDGameController.lua` 函数 `0.19`、偏移 `13914` 构造章节与通信参数并调用 `CreateBHD`；函数 `0.25`、偏移 `20112` 缓存 `DF_CONNECT_DS` 信息。

本轮在安装目录及 `configured installation parent` 范围检索 BHD 程序、BlackHawkDown 路径、对应版本文件和命名包，未找到匹配文件。这里只确认该范围内没有找到，尚未取得平台 DLC 接口返回的实际安装路径。主客户端内的 `CampaignOpening.bin`、`CampaignLoop.bin` 视频和战役菜单不能证明完整扩展包已安装。

`BHDServer.lua`、`MatchServer.lua` 等名称中的 Server 表示这里观察到的客户端通信封装，不能将其作为独立权威战局服务端的证据。

## 靶场实测

使用用户授权的既有独立 shadow 测试，试验目录为 `work/native-client-tests/1791143440200746600`，客户端 PID 为 `98260`。该轮未启用实验战局服务或 Actor 复制探针。

- `03:52:18.227`：`ADFMPlayerController::OnPossess` 绑定 `BP_DFMCharacter_SafeHouse_C_2147477546`；`03:52:18.233` 出现同一角色的 `AcknowledgePossession`。
- `04:03:08.692`：`DFHDKeySettingMgr::OnEnterRange(), 1`。原生画面出现第一人称武器/双手及伤害统计，生命伤害为 `406.3`。
- `04:03:13.040`、`04:03:18.490`、`04:03:31.605`：三个靶子分别发生 `OldS=1 NewS=2`；随后各自出现 `ServerRebornMeFromImpendingDeath` 和复活状态。
- `04:05` 再次观察仍处于靶场；`04:10:25` 至 `04:10:26` 日志记录 `GameOnly → UIOnly → GameOnly`，同一批靶子仍存在。至少跨过大坝现有的 60 秒失败窗口，但不能据此推断大坝可运行。
- 本轮没有获得单独的移动操作确认，也没有证明大坝的出生、物资、AI 或撤离逻辑可在该环境中运行。

`RangeLogic._DebugPrintDisplayInput()` 虽被记为 `LuaMRange: Error`，但源函数 `0.62`、偏移 `46006`、源行 1365–1377 主动使用 `logerror` 输出按键绑定；函数 `0.8`、偏移 `8449` 在进入靶场时调用它。该条本身不能作为异常或卡死证据。日志另有武器外观、音频和投射物配置报错，尚未证明这些条目是大坝控制器为空的原因。

## 原生实现与限制

已经定位并读取 `StartLocalDS`、`SpawnDefaultCharacter`、`CreateGameModeForURL` 和离线初始化入口的注册、包装层及部分实际实现。反射名称和导出数量均不足以证明功能可用。

普通只读访问曾被 `OpenProcess` 错误 5 拒绝。随后通过正常 Windows UAC 授权取得固定入口的运行时代码。最新采样 `1791194884274967600` 核对 21 组注册、4 个类的初始化描述及方法表，均与原版 PE 经 ASLR 重定位后的记录一致；含 143 个入口记录，269 个保存的代码前缀或函数体，合计 83,302 字节。文件头、RVA、长度与代码内容哈希已复核。部分入口只有已校验的 32 字节前缀，不应将入口数量解释为完整函数数量。采样没有调用客户端函数、写入进程内存、读取堆或修改游戏文件。

| 原生入口与证据 | 已确认的行为 | 尚未确认 |
| --- | --- | --- |
| `SpawnDefaultCharacter`，注册 `0x182ae500`，回调 `0xc91dcb0 → 0x9d812d0`，760 字节 | 创建子调用 `0x12a99d90` 为 `SpawnActor`，绑定子调用 `0x1285f1f0` 为控制器 `Possess`；安全屋实测独立确认角色绑定成功 | 大坝是否满足相同的创建与权威条件；未观察到大坝实际进入哪条拒绝分支 |
| `UGPGameplayStatics.StartLocalDS`，注册 `0x16078f50`，`0x5bf4a40 → 0x4d92b70`，147 字节 | 所属类已由类初始化器、方法描述与表内第 1 项确认。默认分支释放字符串后直接返回 `true`；另有运行时替换分支 | 默认返回成功不能证明启动了服务端；替换分支实际运行条件未确认 |
| `UDFMGameInstance::StartLocalDS`，注册 `0x15c23dd0`，`0x2f408f0 → 0x2f3e560`，1,557 字节 | 所属类已确认；处理 `LastMapName`、`LastPlayerIds` 后调用 `OnExecStartLocalDS` 包装层。虚表 `+0x220` 的实际目标 `0x10eb4480` 为 `UObject::ProcessEvent` | 事件的具体 Blueprint/Lua/原生实现，以及是否创建本地权威世界；包装层本身没有证明启动独立程序 |
| `UDFMGameInstance::JoinLocalDS`，注册 `0x15c23e00`，`0x2f40960 → 0x2f3cbb0`，1,491 字节 | 保存 `LastDSAddr`、`LastPlayerId` 后进入 `OnExecJoinLocalDS` 事件包装层 | 具体事件实现和连接条件未确认；本轮未调用此入口 |
| `StartLaunchLocalDS`，注册 `0x18ba2470`，`0xd45eef0 → 0xd421e80`，738 字节 | 比较当前地图、设置客户端无缝切换；任务参数最终交给 `0x114a0c0`，该函数明确引用 `UGPQuestSystem::GotoObjective` | 没有证明它启动独立服务端、创建初始控制器或角色 |
| `UGPGameInstance::CreateGameModeForURL`，包装层 `0x5b9f8b0`，129 字节 | 两个 GameInstance 类的构造函数设置的虚表 `+0x328` 都指向 `0x49a88b0`，1,709 字节。该函数处理 `GAME=`、World、Settings、DefaultGameMode 后调用基础工厂 `0x12924890`，3,151 字节；大坝地图保存的默认类已恢复为 `BP_GameMode_PVPVE_C` | 运行时最终选择是否受到 URL 覆盖、世界权限和该类完整玩法是否可用 |
| `ADFMGameMode`，类描述 `0x1d165fa0`，方法表 `0x182baa00`，75 项 | 构造函数 `0xb883200` 设置虚表 `0x17b21e20`；`+0x7e0`、`+0xb68`、`+0xb70` 的实际函数体分别为 `0xb8edee0`、`0xb8bb400`、`0xb8ba840`，已读取 | 大坝实际是否使用该类或其 Blueprint 子类，以及实例初始化条件 |
| `InitOfflineController`，`0xb8bb400`，2,529 字节 | 按 PlayerId 检查已有控制器；观察者分支退出；通过 `DFMOfflinePlayerController` 类创建 Actor，保存控制器关联，设置队伍及玩家状态并加入待处理队列 | 未证明分配了 `ULocalPlayer` 或本地输入；已有控制器关联和玩家状态仍是运行条件 |
| `InitOfflineCharacter`，`0xb8ba840`，2,454 字节 | 从关联表取得控制器，调用 `FindPlayerStart`、`SpawnDefaultPawnFor` 和 `Possess`，设置 `bIsOfflinePlayer=true`；出生点为空时明确记录失败并退出 | 未确认离线玩家标记在大坝的实际用途；当前大坝是否满足出生点、Pawn 类和权威条件 |
| `SpawnPlayerController`，`0xb8edee0`，1,677 字节 | 解析 Options 内的 `PlayerId`、`FakeLogin`，复用已保存控制器或调用基础创建路径；默认与观察者类分支最终通过 `0x1294def0 → 0x12a9b890 → SpawnActor` 创建 | 控制器 Actor 创建后仍需实际登录、玩家状态及本地输入关联；本轮没有执行此入口 |
| `FindPlayerStart` / `SpawnDefaultPawnFor`，注册 `0x1b2d6050` / `0x1b2d6170` | 注册回调分别跳至 `0x132f0460` / `0x132f1080`，确认为同名事件包装层；原生执行函数 `0x132fa740` 分派至虚表 `+0x6c0`。实际函数体 `0x1294c0a0`，2,770 字节，读取出生点变换并调用 `SpawnDefaultPawnAtTransform` | 出生点有效性、最终角色类以及运行时的 Blueprint 覆盖仍需核实 |
| `GetProjectFilePath`，`0x23ebfa0` / `0x23f5670 → 0x23e39d0` | 已读取 430 字节实际实现，拼接 `.uproject` 扩展名；扩展名常量位于 `0x15a0a0f0` | 路径前缀子调用与实际返回路径尚未观察，不能据此证明工程或服务端存在 |

代码采样中的 `StartLocalDS.static`、`StartLocalDS.instance` 是早期诊断标签，不能用其后缀判断 C++ 的静态/实例方法性质。应以上表的注册 RVA、实测代码和所属类证据区分入口。

原生函数的 unwind continuation 可以指向之前的 continuation。已修正只接受直接指向根条目的采样边界，并验证所有连续片段均回溯到已验证条目、位于可执行映像内，且每个函数不超过 8,192 字节。测试证明采样边界正确，不构成战局能力证明。

`SpawnActor` 含客户端/服务端上下文、空类、抽象类、变换与碰撞等失败条件。`Possess` 的入口检查对象状态后进入权威分支；拒绝路径明确记录“没有网络权威时忽略请求”。这证明创建和绑定不是无条件执行，但不能把静态拒绝分支当成当前大坝失败的已确认原因。

基础 GameMode 工厂保留 URL 游戏类、地图名前缀游戏类及默认类的选择与创建路径。`ADFMGameMode` 的类获取子调用 `0xcb3b106 → 0xce96eb0`、构造包装层及构造函数都已读取并核对哈希；随后读取的虚表和实现证明上述创建路径确实保留在该 Shipping 版本中。大坝默认地图类已由下述序列化属性确认，运行时创建条件仍待验证。

### 离线入口的适用条件

- `InitOfflineController` 接收 TeamId、Camp、PlayerId、NickName、ModeId 和观察者标记。已有 PlayerId 关联会提前返回，观察者也不会进入该离线控制器创建分支。
- 控制器类获取函数 `0xced42c0` 直接引用 `/Script/DFMGameplay` 和 `DFMOfflinePlayerController`。其类元数据中的父类引用入口 `0x1043440` 跳至 `0x133af220`，该函数直接引用 `/Script/Engine` 与 `PlayerController`。元数据参数位置参考 [Epic 类构建 API 签名](https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/CoreUObject/UObject/GetPrivateStaticClassBody?application_version=5.5)，具体入口和字符串均来自本版本客户端。
- `InitOfflineCharacter` 需要先取得已保存的控制器，然后找到有效 PlayerStart。它调用的角色绑定目标与 `SpawnDefaultCharacter` 的 `Possess` 完全一致，因此仍受到已观察到的权威检查限制。
- `bIsOfflinePlayer=true` 是实际代码及日志中的标记；尚未恢复它与本地输入、断线恢复和战局状态的完整关联，不能把该标记直接解释为可操作离线模式。
- 事件名缓存单元在本轮只有运行时名称值，不能当作跨会话固定 ID 使用。`FindPlayerStart` 与 `SpawnDefaultPawnFor` 的身份依据为原版名称注册、直接跳转目标和函数体哈希。
- 同一 GameMode 虚表 `+0x800` 指向 `0x4d84950`。其原版字符串明确标识 `AGPGameMode::RestartPlayerAtPlayerStart`，并包含 NewPlayer 为空或无效的分支；单独存在重生函数不证明大坝已经创建了有效玩家。

以上入口已形成可继续验证的原生路线，但本轮没有新增大坝可游玩的实测结果。

### 启动事件与控制器开通钩子

再次逐份只读解析并核验索引覆盖的 5,707 个 Lua chunk，找到 3 个 `StartLocalDS` 调用函数；没有找到 `OnExecStartLocalDS`、`OnExecJoinLocalDS`、`JoinLocalDS`、`InitOfflineController`、`InitOfflineCharacter` 或 `CreateLocalPlayer` 引用。唯一的 `DFMGameInstance` 命中是调试日志字符串。此结论仅覆盖该 Lua 索引，不覆盖其它 PAK 的加密条目或 Blueprint，不能证明事件实现不存在。

从独立 shadow 的既有 PID `27928` 只读采样三个后续函数，采样目录 `local-runtime-code/1791212348429916800`。全部 275 个保存代码样本的头部、长度和载荷哈希复核通过，载荷合计 84,254 字节；没有读取堆、调用客户端函数或写入进程。

| 已读取位置 | 本版本代码的实际行为 | 仍未证明 |
| --- | --- | --- |
| GameInstance 类获取函数 `0x2f41020` 的 R9 引用 `0x2f417a0`，34 字节 | 回调读取类，给出计数 `10`、名称/代码对表 `0x15c250d0`，再跳至 `0x10d060b0`；后续已读取该分派函数，它逐项处理名称，把名称值及函数指针写入类 `+0x258` 的映射，步长为 16 字节 | 该组注册不覆盖 Blueprint 子类实现或所有反射事件 |
| 表 `0x15c250d0` 的完整 10 对 | 包含 `CollectPGO`、`EnableLuaPerformanceMode`、`JoinLocalDS`、`LuaRuntimeDebug`、`RTS`、`SetCurrentAudioCulture`、三个 ShowLocal 地址/面板入口，以及 `StartLocalDS` | 两个 OnExec 名称未出现在此表，不等于未在 Blueprint 或其它表实现 |
| `DFMOfflinePlayerController` 构造包装层 `0xced43e0`，虚表 `0x187200a0 + 0x3d8 → 0x12d4ddb0`，392 字节 | 从输入游标读一个原始字节，保存至控制器 `+0x524`；检查连接 `+0x58` 非空及其 `+0x98` 指针与当前连接相等；字节为 0 时分派连接虚表 `+0x2c0`，其它值走子连接分支 | 没有读取失败大坝的实际对象；具体连接类的分派实现已在后续采样中读取，但不能判定失败实例在哪个条件退出 |

钩子的原版日志常量为 `Client received PlayerController=%s. Num child connections=%i.`，位于 `0x1b224890`。其职责与 Epic 的 [OnActorChannelOpen 接口说明](https://dev.epicgames.com/documentation/unreal-engine/API/Runtime/Engine/GameFramework/APlayerController/OnActorChannelOpen?application_version=5.5) 对应；网页仅用于接口语义参考，本版本偏移和行为来自实际代码。控制器 Actor 创建后仍需通过连接关联分支，这与旧机“已创建 Actor、但 PC/Owner 仍为空”的记录一致，但尚未证明具体失败原因。

第二次采样前既有客户端结束，工具在未找到唯一 shadow 进程时退出，没有读取进程。之后另一轮 PID `44580` 启动，使用它完成 `0x10d060b0`、`UGPNetConnection` 初始化器 `0x5bf5c30` 及其 helper `0x5db23f0` 的只读采样。两份后续报告分别校验 279 / 281 个代码样本，载荷 84,668 / 84,875 字节。这些采样未启动新客户端或修改 SDK；试验自动关闭及恢复由原启动流程负责。

### 连接的玩家关联实现

后续从既有 PID `43296` 读取连接类获取函数、构造包装层、实际构造函数，以及虚表和直接调用指向的实现。9 份保存报告的代码文件头、长度和载荷 SHA-256 全部复核通过；最新一份有 294 个代码样本，载荷 89,128 字节。没有读取堆对象、修改进程或调用客户端函数。

| 已读取位置 | 核实结果 | 限制 |
| --- | --- | --- |
| 类获取 `0x6042030`，构造包装 `0x6040fb0 → 0x49999f0` | 包装层检查指针非空后跳至构造函数；构造函数写入虚表 `0x15e73e20` | 包装层无独立 unwind 范围，仅校验保存的 32 字节前缀及固定 JNE 指令 |
| 虚表 `0x15e73e20 + 0x2c0 → 0x49b7010`，405 字节 | 原版日志常量明确标识 `UGPNetConnection::HandleClientPlayer`；调用门控 `0x49a3460`，返回 false 则跳过基础绑定 `0x12b91a80` | 存在运行时替换分支；失败实例的门控值和所走分支未观察 |
| 门控 `0x49a3460`，596 字节 | 检查接口 `+0x121` 字节、控制器参数、无缝切换状态及运行时替换；原版无替换分支存在 false 返回 | `SeamlessTravel` 和 `SeamlessTravel with NetActorRemapping` 两个日志分支均返回 true，不能标为拒绝绑定 |
| 接口构造 `0x4999470`，265 字节 | `0x499955b` 向接口 `+0x120` 写入 word `1`；被检查的高字节 `+0x121` 初值因此为 0，门控初始状态放行 | 运行时可以更改状态，初值不能代表失败时的值 |
| 基础绑定 `0x12b91a80`，1,036 字节 | 查找玩家对象，设置控制器关联，并向连接 `+0x30`、`+0xa8` 写入控制器参数；包含原版 `%s setplayer %s` 日志 | 字段写入不等于 Pawn 已 Possess，也不等于持续输入可用 |

实时日志筛选已保留上述入口、基础调用、控制器开通和 `setplayer` 标记。进图报告只保存事件名、次数及首次时间，不复制对象名或连接票据。未打印标记保持未知，因为部分原版日志依赖日志级别；不能据其缺失断定函数未执行。

### 失败试验的传输阶段

重新核对 5 份本机归档 probe 报告。与已保存大坝加载失败快照同为端口 `61908` 的报告位于 `native-client-tests/1791130881345356000/game-server-packets/report.json`，SHA-256 `704eceb1195e7d9a7b6b422a2ae85c09ade5bcd0a68fb39883cd751ce38ea5f8`。

| 该报告的累计观察 | 数量 |
| --- | --- |
| Hello / 已授权登录 peer | 1 / 1 |
| Join | 2 |
| 配置的地图 Actor profile / 注册 bootstrap 集合 | 0 / 0 |
| 已排队 Actor / 已发送初始 Actor 数据报 / 投递 ACK | 0 / 0 / 0 |

这些是整轮累计计数，没有逐次 Join 的时间，不能把两次 Join 全归到首次超时。大坝阶段快照保存原始客户端日志哈希，原日志本轮未重新读取。旧机另一轮试验确有 Actor 创建记录，本机的零计数不适用于那轮。

`collect_map_entry_progress.py` 已保留这些阶段计数及 probe 原文件哈希，缺失或类型不符的旧字段输出为未知；不输出账号、票据或数据报正文，也不从 ACK 推导角色已绑定。这个改动只改善定位信息，没有改变战局行为。

另用现有 Actor 构建器的实际校验规则复核本机 3 份归档复制元数据。1 份未达到完整报告条件；其余 2 份能确认 `BP_DFMCharacter_C` 的 Class 与命名模板，但都不能提供符合规则的 `BP_DFMPlayerController_C`、`BP_GameState_PVPVE_C` 记录。两份均标明复制类缓存、复制布局和属性序列化 schema 未恢复。它们是有范围限制且非原子的注册表扫描，不能据此断定安装中不存在这些类。

已有 257 份明文包头索引中也未命中上述两个 Blueprint 名称；该索引的大小和加密覆盖限制依旧适用。没有用推测的 Class、GUID 或地址替换缺少的原始记录。

当前网络路线应先取得这些真实模板来源和复制协议依据，再生成并发送初始 Actor，按开通、玩家关联、Possess、持续输入逐阶段验证。本地权威世界路线仍需核实 OnExec 事件实现与启动条件。随机出生和高价值物资标记应在真实玩家能够进入战局后恢复，当前均未算完成。

### 原生类默认值与角色创建

原版构造函数与属性元数据共同确认以下字段；这些是原生默认值，不能替代 PVPVE Blueprint 子类的默认对象。

| 字段 | 原生偏移 | 已核实的默认来源 |
| --- | --- | --- |
| `PlayerControllerClass` | `+0x390` | 父类构造函数调用 `0x6051480`，直接引用 `/Script/GPGameplay.GPPlayerController` |
| `DefaultPawnClass` | `+0x3a8` | 基础构造函数调用 `0x132da770`，直接引用 `/Script/Engine.DefaultPawn` |
| `HUDClass` | `+0x3a0` | 父类构造函数调用 `0x313f550`，引用 `BaseHUD` |

角色创建链已从 `SpawnDefaultPawnFor` 继续核对到 `SpawnDefaultPawnAtTransform`：事件执行函数 `0x132fa620` 分派至虚表 `+0x6b8`，ADFM 实现 `0xb8edb70` 调用父类 `0x4d92080`。父类先通过 `GetDefaultPawnClassForController` 取得角色类，常规分支再调用已确认的 `SpawnActor`。后者的原生实现 `0x1292ed90` 读取 `+0x3a8`，检查是否为 `Pawn` 类，类型不符则返回空。这里未证明实际选中的 Blueprint 默认类，也未证明当前大坝执行了哪条分支。

### 战局初始化与玩家资料

| 入口与原版定位 | 已核实行为 | 适用边界 |
| --- | --- | --- |
| `ADFMGameMode::InitGame`，`0xb8b4e70` | 先调用父类 `0x4d0a020`，再通过 `0xb8aa810` 获取已创建的 DFMDSLogic，保存至 GameMode `+0x628`；空值有明确错误日志 | 获取函数读取 `+0x5f0`，自身不创建对象 |
| `AGPGameMode::InitDSLogic`，虚表 `+0xaa0 → 0x4d09d10` | 读取 GameMode `+0x5e8` 的配置类，以 `/Script/DSNetwork.DSLogicBase` 检查类型，通过 `0x10ebd0a0` 的对象创建路径创建并保存至 `+0x5f0` | ADFM 原生构造配置该类为 `DFMDSLogic`；未观察到大坝实例实际完成此步骤 |
| `ADFMGameMode::InitGameState`，`0xb8b51e0` | 调用父类后检查 GameState 类型，保存 DFMGameState 关联；类型不符会记录转换失败 | 不能以函数存在证明实际 GameState 已创建 |
| `ADFMGameMode::InitNewPlayer`，`0xb8b6630` | 解析玩家及队伍参数，从 `+0x628` 的逻辑对象通过 `0xb745670` 按 PlayerId 查资料；该查询访问 DSLogic `+0x4f0` 表 | 缺资料会记录 `PlayerInfo is not found` 后继续部分默认值；玩家状态类型不符会返回 `PlayerState is not ADFMPlayerState type` 错误，二者行为不同 |
| `UDFMDSLogic::ProcSyncPlayerReq` 对应回调，`0xb767300`，5,325 字节 | 实际注册消息是 `pb.Any2DsSyncPlayerInfoReq`。解析后在 `+0x4f0` 表中新增或更新玩家资料，之后检查玩家令牌；部分半途加入分支还有前置检查 | 原生诊断字符串沿用 `SDsaSyncPlayerInfoReq` 名称。未恢复完整传输封装，也未向客户端发送或注入这条消息 |

`DFMDSLogic` 构造函数 `0xb71cc60` 初始化 `+0x4f0` 表，并注册上述消息回调。消息名称由原版映像的三段常量与原生名称构造代码共同复核，不是由旧日志名称推定。

本机重新提取 PAK entry `33863680` 的 `@zone2dsa_editor_pb.lua`，179,463 字节，SHA-256 `14d9fa6ebed0c75fdcb4afc3b980ac44ef350dadce6ef5be3ae3d6cfc828adc2`，与现有字段目录的来源一致。`Any2DsSyncPlayerInfoReq` 的编码、解码函数为 `0.43` / `0.42`：字段 `1` 为重复的 `DsPlayerInfo`，字段 `2` 为 `room_id`。`DsPlayerInfo` 编码、解码函数 `0.39` / `0.38` 中，`player_id=1`、`team_id=11`、`mode_id=13`、`ds_token=14`、`is_observer=86`。这些是该消息的字段号，不能与大厅 `MatchPlayerInfo.ds_token=24` 混用，也不能把原生内存偏移当作协议字段号。

已建立的静态链为：配置并创建战局逻辑对象，接收玩家同步消息，保存玩家资料，登录时查表，创建角色并尝试绑定。仍需核实零售客户端如何启动该权威世界、实际 Blueprint 角色类、本地玩家与输入关联。当前 Python 诊断服务的令牌和玩家记录没有证明能自动填入这个原生表。

### 大坝实际地图配置

只读检查安装包 `pak-0-1-pakchunk84-WindowsClient.pak` 的主地图资源，确认以下两份 World 包；这里没有调用客户端函数或修改地图。

| 包路径 | UAsset 条目 | 数据体内容 | Level 的 WorldSettings |
| --- | --- | --- | --- |
| `/Game/Maps/Dam_Iris_Level1/Dam_Iris_Level1` | `30241`，SHA-256 `9fadaef35396d9ca5c133d4fc4cdaf9036e5a17e245153f3a0a66fb566d0879f` | 条目 `30240` 与 `30268` 内容完全一致，SHA-256 `c98aa4b66503c462b203a843c5f128e254b4314889c52e90a26ea3a50d3010ee` | 导出 `22` 的 `WorldSettings` 指向导出 `18` |
| `/Game/Maps/Dam_Iris_Level11/Dam_Iris_Level11` | `30269`，SHA-256 `96eee4132b3bd6c5a83c9dbaadf5e1484198ac47eb36321fe90df0c085464195` | 同一数据体内容；按完整导出长度、名称表和全部 29 组属性列表核对 | 同一引用链 |

两包均有 29 个导出，数据体为 8,696 字节加 4 字节包结束标记。配对依据为完整导出范围、逐字节相同内容及所有导出的类型化属性列表，合计验证 58 组；不能按相邻 PAK 条目直接配对。条目 `30270` 是 6,307 字节，不能作为 `30269` 的数据体。四个相关源条目的 PAK SHA-1 与安装文件中的压缩数据一致；早期扫描的 `entry_sha1_matches_payload=false` 比较的是解压内容，不能将它误解为压缩数据校验失败。

实际选择链及数据体偏移为：

- `PersistentLevel` 导出 `22` 的 `WorldSettings` 为 `ObjectProperty`，值为导出 `18`。其属性和值的精确偏移保留在证据文件中。
- 导出 `18` 的类为 `/Script/DFMGameplay.DFMWorldSettings`；`DefaultGameMode` 标签位于 `5298`，值位于 `5323`，4 字节对象索引为 `-3`，解析到 `/Game/BluePrints/GameModes/TestGame/BP_GameMode_PVPVE.BP_GameMode_PVPVE_C`。
- 导出 `20` 的 `GPWorldSettings` 保存了 `BP_Test_GameMode_C`，但未被上述 Level 的 `WorldSettings` 引用。导出 `29` 的普通 WorldSettings 也未被选中。
- DFM 配置另有 `bEnableLooting=true`、`SubsystemConfig=BP_LevelSubsystems_SOL_C` 及 `GameRuleSettingConfigClass=BP_GameRuleSettingConfig_SOL_C`。`MapType` 原始整数为 `10`；本轮没有为它推定枚举含义，也没有从启用物资的开关推定服务器掉落规则。

重新核对已有明文包头索引的 257 份安装 PAK，文件长度及页尾哈希均一致；未在已成功解析的包归属路径中定位上述 PVPVE/TestGame/LevelSubsystem 蓝图本体。另外重新解码并检查 67 份含 BlueprintGeneratedClass、但缺少包归属路径的明文包头，以根导出名称和源哈希复核，仍未命中上述目标。该索引解码上限为 256 KiB，加密条目、较大条目及无法解析的包未覆盖，因而不证明这些蓝图在安装中缺失。Blueprint 的 PlayerControllerClass、DefaultPawnClass 和事件实现仍待恢复。

本轮 1,800 秒试验已自动结束，PID `98260` 对应的归档报告 `client-observation-1791145466305663300.json` 记录 `original_sdk_restored=true`；结束后核对 shadow 中恢复的 `rail_api64.dll` SHA-256 为 `9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723`，与原 SDK 相符。随后另一个测试启动了 PID `103208`，因此当前公共报告和当前 SDK 状态不能替代本轮归档记录。

随后原生代码采样所用 PID `114416` 的 1,800 秒试验也已自动结束：观察时间 `2026-10-04T20:58:08.476299Z`，实际持续 `1800.12` 秒，包装器结束时间 `2026-10-04T21:28:11.587900Z`。报告记录 `original_sdk_restored=true`；首次恢复遇到 Windows 错误 5，重试 1 次后成功。结束后源安装和 shadow 的 SDK 哈希均为上述原 SDK 哈希，且未发现残留客户端进程。该轮没有启用实验战局服务，没有新增大坝进图成功证据。

PID `10324` 的后续 1,800 秒试验于 `2026-10-05T09:50:29Z` 结束；对应报告为 `client-observation-1791193935927252200.json`，`root_pid=10324`、实际持续 `1800.98` 秒、`original_sdk_restored=true`。归档文件名中的时间是下一次启动时归档上一轮报告的时间，不能据文件名认定其试验开始时间。`client-observation-1791192017735928000.json` 保存的是更早的 PID `30612`，不属于 PID `10324`。最新代码采样来自 PID `40540`；该轮未启用实验战局服务，`18:04:35` 点击出发返回 `139005` 维护响应，不能作为新的大坝加载失败复现。

PID `40540` 的本轮试验已于 `2026-10-05T10:22:24Z` 自动结束，实际观察 `1801.03` 秒，结束原因 `observation_limit_reached`。独立保存的 `map-parent-world-init-client-observation-20261005.json` 已核对 `root_pid=40540`、`record_complete=true`、`original_sdk_restored=true`。结束后 source 与 shadow 的 SDK SHA-256 均为 `9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723`，原客户端与试验包装器均已退出。

Unreal 的通用专用服务器构建需要游戏 C++ 工程，并使用独立 Server 构建目标；仅有通用引擎源码和已打包客户端不足以据此构建本游戏的同版本服务端。参见 [Epic 4.27 专用服务器文档](https://dev.epicgames.com/documentation/en-us/unreal-engine/setting-up-dedicated-servers?application_version=4.27)。

## 验证路线

1. 控制器、默认 Pawn 和 DSLogic 创建，以及玩家同步、登录查询的原生链已读取。继续核查 `OnExecStartLocalDS`、`OnExecJoinLocalDS` 的事件实现和实际启动路径，确认可否建立本地权威世界及玩家输入关联；不能通过手工填 Python 玩家记录替代原生初始化。
2. 大坝主地图的 `WorldSettings → DefaultGameMode` 静态引用链已恢复，默认类为 `BP_GameMode_PVPVE_C`。继续读取该蓝图的 PlayerController/Pawn 类默认值与进入 URL，核对是否存在运行时覆盖，并确认与上述原生入口的对应关系。
3. 靶场角色绑定、射击伤害和靶子复活已有实测证据，移动操作仍待确认。大坝需要单独验证权威世界初始化、实际控制器与角色绑定、本地输入，并记录创建失败发生在哪一步。
4. 若大坝能够建立真实控制器与角色绑定并持续接受输入，再按客户端配置恢复出生、物资、AI 和撤离。若客户端不具备所需权威逻辑且没有同版本服务端组件，则转入战局协议与复制行为恢复，先完成 PlayerController、PlayerState、GameState、Pawn 的创建与绑定，再处理玩法。

判断进图成功需要真实角色绑定、可操作移动与射击，并跨过当前 60 秒失败窗口持续运行。资源加载结束、控制握手完成或诊断消息获 ACK 均不能替代该验证。

## 本机证据

- [Lua 扫描及源哈希](../work/evidence/map-local-runtime-all-lua-scan-20261005.json)
- [靶场及教学函数记录](../work/evidence/map-local-runtime-entry-functions-20261005.log)
- [编辑器条件与安全屋 Possess 记录](../work/evidence/map-local-host-and-possession-20261005.log)
- [本地 DS 命令构造](../work/evidence/map-local-ds-launch-entry-20261005.log)
- [四模式入口记录](../work/evidence/map-mode-entry-lua-20261005.json)、[战役启动与 DLC 记录](../work/evidence/map-bhd-launch-and-dlc-lua-20261005.json)
- [安装程序 PE 元数据](../work/evidence/map-installed-client-pe-summary-20261005.json)
- [原生符号候选](../work/evidence/map-local-runtime-native-bindings-20261005.json)、[磁盘代码前缀](../work/evidence/map-local-runtime-static-code-prefixes-20261005.json)、[只读访问结果](../work/evidence/map-local-runtime-code-read-attempt-20261005.json)
- [本轮安全屋与靶场日志](../work/evidence/local-range-trial-1791143440200746600-alerts-20261005.log)
- [正常 UAC 后的固定原生代码采样](../work/evidence/local-runtime-code/1791145233023400600/result.json)
- [原生代码所引用的原版映像字符串](../work/evidence/local-runtime-source-string-references-20261005.json)
- [靶场调试输出与本地 DS 调用所属 Lua upvalue](../work/evidence/local-range-debug-and-ds-upvalues-20261005.json)
- [本轮客户端观察与 SDK 恢复](../outputs/native-account-provider/client-observation-1791145466305663300.json)
- [固定代码、调用与归档记录验证](../work/evidence/local-runtime-validation-20261005.json)
- [GameMode、类归属和离线入口的完整原生采样](../work/evidence/local-runtime-code/1791149012328330500/result.json)
- [权威检查及工厂的原版字符串引用](../work/evidence/local-runtime-authority-source-references-20261005.json)
- [103 个保存代码样本及类归属复核](../work/evidence/local-runtime-authority-validation-20261005.json)
- [离线初始化、控制器与出生事件的最新完整采样](../work/evidence/local-runtime-code/1791172001069063200/result.json)
- [离线实现的原版字符串和事件注册对应关系](../work/evidence/local-runtime-offline-implementation-references-20261005.json)
- [157 个保存样本的哈希和边界复核](../work/evidence/local-runtime-offline-validation-20261005.json)
- [大坝主地图明文提取记录](../work/evidence/dam_main_world_settings_20261005/manifest.json)
- [实际 WorldSettings 与默认 GameMode 属性](../work/evidence/dam-active-world-settings-20261005.json)
- [安装 PAK 条目的压缩数据校验](../work/evidence/dam-root-package-source-validation-20261005.json)
- [已有 257 份 PAK 包头索引的蓝图归属复核](../work/evidence/dam-game-mode-package-ownership-check-20261005.json)
- [67 份无归属明文包头的根导出复核](../work/evidence/game-mode-blueprint-unowned-header-check-20261005.json)
- [原生类字段与构造引用](../work/evidence/game-mode-class-fields-source-20261005.json)
- [默认 Pawn 与按变换创建的实现](../work/evidence/local-runtime-pawn-at-transform-source-references-20261005.json)
- [世界初始化实现的原版字符串引用](../work/evidence/local-runtime-world-init-source-references-20261005.json)
- [最新 269 个代码样本的边界与哈希复核](../work/evidence/local-runtime-world-init-validation-20261005.json)
- [玩家同步回调、消息常量及本机 Lua 源校验](../work/evidence/local-runtime-ds-player-sync-evidence-20261005.json)
- [PID 10324 的完成报告与 SDK 恢复](../outputs/native-account-provider/client-observation-1791193935927252200.json)
- [PID 40540 的已脱敏日志快照](../work/evidence/map-parent-world-init-client-snapshot-20261005.log)
- [PID 40540 的独立完成报告](../work/evidence/map-parent-world-init-client-observation-20261005.json)
- [重新核验的 Lua 启动事件扫描](../work/evidence/local-ds-event-lua-scan-20261005.json)
- [归档试验的 Actor 传输缺口](../work/evidence/map-entry-transport-gap-20261005.json)
- [新读取的启动与控制器钩子及 275 个样本校验](../work/evidence/local-runtime-followup-validated-20261005.json)
- [玩家关联实现及 9 份原生采样校验](../work/evidence/local-runtime-player-binding-validated-20261006.json)
- [本机复制元数据来源可用性核查](../work/evidence/map-local-metadata-availability-20261006.json)

本轮只读采样测试 20 项、函数边界测试 3 项、日志监视测试 5 项，合计 28 项通过。日志监视新增保留原生世界初始化、玩家资料缺失、玩家状态类型错误和玩家同步消息。当前采样器的 21 组注册、52 个固定前缀和静态虚表指针也通过源安装及 shadow 版本校验。测试覆盖诊断工具的边界、哈希与引用验证，未验证大坝实际玩法。

后续增加采样依赖顺序检查，采样器测试为 21 项；新增传输阶段与隐私过滤后，进图报告测试为 8 项。当前静态计划含 21 组注册、53 个固定前缀；后续计划中的新目标不等同于已完成的运行时代码采样。

此前执行采样器 21 项、函数边界 3 项、日志监视 6 项、主地图属性 6 项和进图报告 8 项，合计 44 项通过；源安装与 shadow 静态计划校验、`git diff --check` 通过。验证对象为诊断工具，未新增大坝可操作验证。

2026-10-06 最新核查执行采样器 24 项、函数边界 3 项、日志监视 7 项、主地图属性 6 项、进图报告 11 项，合计 51 项通过。新增检查覆盖构造包装层的固定 JNE 来源、后续采样依赖顺序、玩家关联阶段统计及隐私过滤。源安装与 shadow 的静态计划校验、`git diff --check` 再次通过。当前共享日志快照没有新的进图或玩家关联标记，不能把本轮代码采样视为新的大坝复现或修复验证。

主地图属性检查工具 `work/inspect_dam_world_settings.py` 复用了现有类型化属性解析器；伴随资源的等价内容、错误配对、结束标记、修改后哈希及证据路径检查共 6 项测试通过。工具输出明确保留 `map_playable_verified=false`。

以上原始证据位于本机 `work/evidence`，未随本次调研推送到 GitHub。本报告没有将待验证能力列为已完成进度。
