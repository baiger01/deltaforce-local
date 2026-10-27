# 全玩法接入调研与实施依赖

**工作区状态更新（2026-10-22）：** 用户指定 `repository root` 为唯一正式开发与运行目录。本文对 `deltaforce-map-appearance` 的路径、源码和采样结论保留为当时的历史观察，不代表当前主工作区的实现或缺口。旧工作区完整归档于 `historical-map-archive/files`；需要复核旧引用时，在该归档中定位原相对路径，不从归档运行服务或自动合入代码。接手修复必须重新核对当前主工作区及最新用户实测。

日期：2026-10-20。对象：`historical map checkout` 的当前地图实现，以及 `deltaforce-local` 的大厅库存契约。本轮完成只读调查、离线复现和协作说明，没有修改地图运行源、启动游戏或写入账号。本报告是开发交接依据，不是完整玩法验收记录。

**阅读时点：第1至8节保留07:51 UTC审查背景；第9、10节记录后续恢复及协作者代码变化，第11节记录10月20日继续追查，第12至14节记录北京时间10月21日的进一步收窄。绑定白名单和移动时钟/拒绝统计以第10节为准；医疗参数及门卡/撤离判定以第11节为准；射击可选数据、AI巡逻脚本和SOL终局hook依赖以第12节为准；世界运行时当前安装状态以第13节为准；奔跑体力、首次技能对象与冷却、F输入勘误及独立地图难度语义以第14节为准，不再将早先未闭合项当作永久结论。**

原生来源限定客户端 SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。细节分别见 [角色与技能](GAMEPLAY_CHARACTER_RESEARCH_20261020.md)、[战斗与 AI](GAMEPLAY_COMBAT_RESEARCH_20261020.md)、[世界与终局](GAMEPLAY_WORLD_RESEARCH_20261020.md)。每份报告配有来源文件、函数、真实字段和逐文件哈希。联局与账号证据见 [会话契约 JSON](../work/evidence/gameplay-session-research-20261020.json)，可用 [只读复核脚本](../work/research_gameplay_session_contract_20261020.py) 重建。

## 1. 审查结论

现有工作已经接通出生、拥有者、真实携带快照、部分普通移动、技能实体/模板初始复制、武器初始状态及拥有者切枪分派。但不能据此宣称已恢复可玩的服务器。主要缺口分布在客户端状态前提、准确协议、服务端规则执行、结果复制及最终账号保存之间。

1. **P1：世界运行时没有真正安装。** [install_runtime](../work/portable_durable_world_runtime.py:165) 仍返回 `installed=False`：缺本局 PackageMap/Actor 绑定、权限、位置和真实终局提供者。箱体 codec、独立 SQL 事务和 ACK 队列已有实现，尚未构成实际玩家 F 开箱、搜索、拿取、撤离的生产流程。不能以恒真 callback 绕过这些前提。
2. **P1：技能和战斗缺权威执行。** 当前技能实体与若干模板已正常存在，但未接首次激活/取消、充能与冷却、任务效果；生产收件链也没有已证实的开火、命中、战斗换弹、用药和伤害执行器。客户端收包、模型或图标出现，均不能代替这些处理。
3. **P1：角色状态与武器表现仍有前置缺口。** generic FSM initialized/started 已为真；角色 `bFSMIsInited` 是真实 Net h6，当前未发送，实际值未采样。两把实际枪初始化完成、第二把 active，但保存观察中 1P mesh 隐藏且没有 AttachParent。不能通过强写 initialized/hidden、把 HP 改成200或凭字段名称改权限解决。
4. **物品契约：早先绑定不兼容已发生变化。** 07:51的无数据库调用复现过 `bind_type/bind_player` 被拒绝；第10节的新探针已通过，当前源码也增加根物品与枪内弹药绑定的保存。该旧白名单错误不再列为当前阻塞；医疗/护甲状态的完整保存与原生整局结算仍需单独闭合。
5. **P1：入局与账号间缺物品托管生命周期。** 快照只冻结数据，未预留携带实例；最终 materializer 会检查账号是否被并发修改，但这是拒绝冲突，尚未提供入局期间的单一物品归属和重连恢复策略。没有该流程，物品增减和终局落库不能作为完整一局验收。
6. **P2：移动的范围比“能走动”窄。** 普通零扩展消息有接收器，base/bone、custom、vault 与扩展数组仍拒绝；MoveFlags/packed mode 没有完整动作语义、碰撞重演、纠正、体力 tick。后续代码已新增时钟恢复、合并消息预算和拒绝原因统计（第10节）；不能继续以旧源码断言没有这些逻辑，也未据此确认实机移动问题已解决。

这些不是同一个 bug，需分别按来源、调用方与事务闭合。不能再统一归因于“缺几个复制字段”，也不能把所有未知项都称为客户端缺资源。

## 2. 什么证据能说明什么

- **原始契约**：安装 PAK、Lua、配置、连续 native 函数、UHT、实际 ClassNetCache/FunctionRepLayout。确定真实身份、方向、字段和消费者；函数声明及内存大小不等于线格式或服务器算法。
- **实现接入**：实际 production caller、owner/代际校验、请求解码、权威状态提交和结果投递。独立 helper 或测试通过只能证明自己的实现。
- **原生观察**：同一 trial、同一对象、明确时点的字段或请求。拒绝读取保持未知；数组容量不当作个数，两个不同时点不拼成原子状态。
- **操作验收**：实际输入 -> 请求 -> 服务器判定和前后状态 -> 客户端消费者 -> 保存重开；同时覆盖取消、失败和重试。网络 ACK 仅证明交付，不证明权限、效果或结算成功。

各领域报告保留旧证据及时间，当前结论优先于历史综合报告。协作者仍有未提交工作，Git HEAD 不能代表工作区内容；后续复核须用逐文件哈希和新试验封存记录。

## 3. 全流程与唯一状态所有者

完整一局应连续经过以下阶段，而不是在各模块创建互不关联的“当前数据”：

1. 大厅确定账号、模式、地图、任务、干员外观和实际携带物品。
2. 同事务冻结携带快照，预留根物品、配件、枪内弹药、容器和权限；分配唯一 admission、room seed、generation。
3. 同局来源生成 Prepare、地图/出生、PC/Pawn/PS、拥有者及真实 Actor/组件映射。
4. 原生完成接管、角色作者状态、技能和武器初始化，服务器形成可用角色状态。
5. 当前玩家操作进入同一局的移动、技能、战斗、交互与物品命令处理；统一服务时钟、位置、归属、revision、命令去重及 outbox。
6. 服务端撤离、死亡、超时或主动退出规则产生唯一终局，冻结 carry-out 与全部消耗/产出。
7. 同一账号事务保存物品、弹药、状态、门卡、货币及有权威证据的任务变化，持久保存不可变结果。
8. 发布原生终局和业务 Settlement，客户端回大厅；重查、断线与重连只重放已有结果。下一局不能复用旧世界命令。

建议的本地生命周期为 `Reserved -> Running -> TerminalPending -> AccountApplied -> LobbyDelivered`，另定义有资格的取消和重连。**这是本地设计建议，不是声称恢复官方服务器状态枚举。** 具体原生消息只使用已有来源。

### 现有会话实现应保留的部分

[native_match_loadout.snapshot](../outputs/df-local-server/dfserver/native_match_loadout.py:26) 在同一认证 SQLite 事务读取真实携带、已选干员/外观、组件、枪内弹药、近战和容器。不可变字节进入 ticket，由 [issue_match_admission](../outputs/df-local-server/dfserver/game_server_probe.py:418) 的同次工厂生成 Actor 与控制计划。不要另造默认枪或从另一份账号快照补角色。

[native_match_materializer.materialize](../outputs/df-local-server/dfserver/native_match_materializer.py:279) 已要求当前事务中存在完全相同的终局收据、账号映射、carry-in 比对、GID 无碰撞、真实几何、写后重读和重复收据幂等。它是有效的持久化基础；缺的是合法终局生产者、完整特征兼容以及前置的物品托管，不能把这些校验删掉来凑成功。

两个 checkout 的 `work/native-test-account/save.sqlite3` 是不同路径。[启动器](../work/verify_local_provider_client.py:1207) 按各自 ROOT 选择账号。统一代码时需明确哪个存档是权威及迁移版本，不能直接复制覆盖其中一个。

## 4. 分玩法覆盖与未接部分

### 角色、出生、运动

- **出生/控制权**：真实 MS23 模板与 RNG 子集、单人出生分配、PC/Pawn/PS、ClientRestart、朝向和基础 HUD 已有链。地面/胶囊安全、所有随机点、队伍分配、重部署与复活需独立恢复。
- **普通移动**：实际 `CharMoveComp.NewServerMove6/max10` 有 codec 和 admission consumer。需要逐原因记录拒绝，恢复时间戳 reset/序号回绕、纠正与位置同步；交互、射击和 AI 共用该权威位置。
- **奔跑/体力**：已有真实输入、Sprint.CanSprint、FSM 和 Stamina 数据来源；最新100/100不说明消耗/恢复已运行。缺 Shift 按/放瞬间状态证据、作者子图进入和服务 tick。
- **姿态/跳跃/滑铲/翻越/游泳/基座**：有真实字段或扩展 serializer 分支，未闭合动作 flags/mode、碰撞、体力、模式切换和网络纠正。每类分别验收。
- **角色 FSM**：先读当前 h6、identity/databoard、local active nodes、子 FSM context 和动作订阅。只有真实初始化语义成立后才发布正常 Net h6；不能直接改进程内部位。

### 干员技能

- **已接身份与模板**：选择干员 -> Expert -> SkillData -> 实体/槽 -> 当前模板收集与初始复制；最新实体11、槽5，多项 instance/template 可解析。仍有个别 type0/spawnstate1 分支待核对。
- **首次激活与重复按键**：`ServerTriggerBehavior46/max98`的真实layout及presence/enum6/signed32参数codec已经闭合。追加调查已由原生构造、排序与叶子serializer恢复30/31/38标准参数grammar（第11节），不能继续称其参数排列未知；当前连接profile、自然请求对照及实际执行仍未验证。重复按键不能替代首次激活。
- **执行/取消/充能/CD**：当前没有执行分派与计时。需根据真实 CdID、模式 override、任务参数、执行ID及合法取消，原子修改充能、冷却和效果。不能统一返回 cast success。
- **效果类别**：冲刺/Buff、投掷与射出物、治疗、烟雾、救援/召唤、位移等按实际 task 建生命周期、碰撞/目标、持续时间、回收与复制。一个模板收集图不能充当所有技能执行器。

### 武器、战斗和医疗

- **入局/显示/切枪**：真实配方与两枪初始状态已接；owner switch 已进入生产收件/响应/重传/ACK流程，不能再称没有 caller。第一人称挂接仍未通过，需要合格 appearance/proxy/mesh 回调观察。
- **瞄准/开火/命中**：`ServerProcessWeaponEventDataForFire49`、`ServerProcessWeaponEventDataForHit50`、`RPC_RequestServerHitAction42`、`SendReportClientHit45`等候选有真实 owner/cache 来源；最后一项是客户端命中报告，反向 `RPC_ClientApplyHitAction` 为index40。尚缺完整 serializer 和 production authority，客户端自报伤害不能直接扣血。
- **装填/弹药**：大厅拖弹已实现，不等于战局 reload。需追 Firing/ChangeClip、分阶段换弹和 InventoryManager 卸弹51，统一枪膛、弹匣、备用弹、弹种、计时与取消。
- **生命/防具/异常状态**：Health、ArmorHealth、Durability 是不同状态；防具公式引用、部位医疗、出血/损伤/镇痛/Buff 需要独立配置与执行。不能统一“扣耐久”或“加总血量”。
- **用药**：真实 Health UI 与轮盘两条路径已查，UseItemManager 的 ServerAttemptUseItem14、Cancel13、Select15 有 cache 来源。追加调查已恢复14参数schema及13取消参数codec（第11节）；起止计时、打断、部位/修甲、消耗品耐久、finish/fail 与库存 delta 仍未接完整运行链。
- **投掷/近战**：选择刀、投掷模式或 Actor 存在不能说明攻击可用。需真实攻击序列、动画窗口、轨迹/遮挡/距离、目标效果、消耗和回收。
- **倒地/救援/死亡**：需真实队伍、距离、倒地状态、救援计时和最终死亡。尸体是一次性的物品所有者，不能复制一份入局装备；安全箱等保留规则必须明确。
- **AI/BOSS**：真实 Pawn、Controller、BT、模板与复制字段存在；当前没有已证实的巡逻、感知、导航、追击、射击、承伤、死亡与掉落运行链。BOSS阶段、特殊兵、专属任务/掉落不能由普通 AI 替代。

### 世界交互与物品

- **地图加载/身份**：三个保险箱已找到同 World.Levels/Outer/visible，未通过当前 PackageMap 与 ActorChannel 绑定；未匹配 StreamingLevels 不能自动判未加载。静态 Actor 不得另外生成同名动态副本。
- **F交互/普通门/卡门/密码/破坏**：SOLInteractor71/72 有来源，当前 decoder 只支持限定保险箱标签。恢复实际锁、门/卡映射、权限和耐久一次性消耗；密码、破坏与电梯/索道按地图独立处理。
- **开箱/搜索**：PC226、箱体 h103/h113 和有限4x4 producer已有独立实现；搜索队列、占用、逐物揭示、打断和真实计时未接。源 BaseItemSearchTime=3 不能推广到所有物品。
- **拿取/库存**：InventoryManager ItemMove45已有34-command布局及整堆普通实例 SQL。拆分、合堆、交换、旋转、装备/配件、弹药、自动摆放、容器连带要共享同一实例账。
- **丢弃/拾取/尸体**：需要动态 Actor 的真实类与复制、单份物品所有权、partial-stack 新GID、empty/销毁和重拾。不能只删除大厅物品或刷新背包图标。
- **地图标记/任务**：高价值数组已出现2项，但 Actor 未绑定；PS任务未初始化。任务须按真实目标区域/对象、击杀/撤离等服务器事件推进，不能由客户端请求或测试完成开关授予。
- **地图曼德尔**：Prepare 的生成器/事件选择已有来源；世界 BlueprintPlunder 本轮为null。携带、通缉、掉落、解码/回收计时、争夺和带出未闭合。大厅抽奖扫描成功不能覆盖这条链。
- **撤离**：单张大坝有8个真实静态出口及负重、装备、付费、水闸等分支；当前 AllocatedExits为空。需实际Actor、当局开闭选择、范围/条件/人数、计时和取消，完成后产生唯一终局。

### 地图、模式与额外分支

当前实际发布入口仅 `2201 / Dam_Iris_Level1 / match_mode_id=142201103`，两条业务 operation 不能算两种地图。真实MapInfo的六个地图族为 `Forrest / Dam_Iris / SpaceCenter / Brakkesh / Tide / AZ-5`；追加调查已从原表恢复六条mode→map→SubWorld关联（见第9节），但其余地图当前board的point_id和开放状态仍未闭合。门卡地图分区、MapInfo/MapType 与 admission MapID不可互换。六图仍需分别建立完整加载、真实Actor、物资、事件、出口和任务矩阵。

全面战场、挑战等具有自己的角色、部署、得分和结算分支；地图报告与战斗报告的范围普查记录原生模式、载具/固定武器、部署复活、占点、局内商店和特殊交互的真实来源及尚未闭合项。MapInfo还含征服/突破/夺旗/据点/空战/爆破等资源分支，但资源存在不能当作当前开放清单。当前普通 SOL 的 PS170/171、单人 team策略、三箱或八出口不能直接套给它们。

本轮的“全玩法”是把现有客户端中需要接入的分支与缺口纳入调查清单，不是宣称全部模式/所有技能的线上参数和官方服务器规则已经反编译完毕。无来源的算法、模式专有布局和个别资源关联继续标未知，不补假ID或借用其它模式的成功状态。

## 5. 大厅、任务、设施与结算联动

大厅的买卖、配件、枪内弹药、卡包、安全箱、药品、任务奖励、部门与设施已经有独立实现和部分用户实测。它们与战局必须共用物品语义，但不能混用消息入口。尤其要对齐：

1. **绑定**：本会话 [native_prop_bindings](../outputs/df-local-server/dfserver/inventory/native_prop_bindings.py:34) 与 [库存投影](../outputs/df-local-server/dfserver/app/core.py:712) 会返回绑定。早先地图白名单拒绝绑定的复现保留为历史；当前 [materializer](../outputs/df-local-server/dfserver/native_match_materializer.py:27) 已接受成对绑定字段，并在根物品与装填弹药保存时调用绑定 writer。第10节记录最新探针及仍需验证的完整持久流程。
2. **完整特征**：组件树、根/弹药GID、皮肤/挂饰、旋转、容器空间、绑定、医疗耐久、防具两组数值、门卡耐久、权限/有效期需要有版本的统一表示。当前 materializer 仅允许门卡 health，不能覆盖全部战斗磨损。
3. **任务与成长**：入局冻结已接受任务版本；真实击杀/交互/区域/撤离事件在唯一记录上更新目标。终局奖励、经验、声望再进入现有任务领奖与设施前提流程，不能重新写死部门满级。用户要求的测试完成开关默认关闭，保持与真实事件分离。
4. **货币与箱子**：付费撤离、局内商店、任务现金目标、物资带出不能各自改一份余额。藏品箱/仓库扩容是大厅持久设施，不得当战局背包容量；进入战局只冻结真正携带的实例及权限。
5. **异常恢复**：只锁本局携带实例；未携带仓库物品可按明确策略操作。持久托管键为 admission 加 reservation revision；transport generation只隔离网络命令/投递。重连的新generation恢复同一份托管，崩溃收尾不依赖已失效的旧generation；不能盲目释放所有旧局或从初始快照再赠物。

## 6. 建议实施顺序

1. **统一来源与存档契约。** 冻结要合并的工作区文件哈希、客户端与目录版本；修绑定/状态兼容，定义持久入局预留和生命周期。用隔离存档验证，不覆盖任何真实账号。
2. **角色可操作。** 闭合 FSM 真实就绪条件和 1P 武器挂接；补移动拒绝原因与恢复，取得走/跑/体力、实际切枪的完整操作证据。之后世界范围、命中与AI都消费同一有效位置。
3. **先做一个技能闭环。** 按真实当前干员恢复首次请求、可用条件、充能/CD、task执行、取消及结果。再按技能家族扩展，不批量发送假成功。
4. **先做一个世界闭环。** 同局真实Actor -> F提示/权限 -> 解锁/搜索 -> 整堆拿取 -> 背包/箱双侧变化 -> 持久 journal/outbox。再补拆分/交换/装备/丢弃、普通门和卡门等分支。
5. **完成普通战斗及一个AI闭环。** 可见枪 -> 切枪/瞄准/射击/换弹 -> 弹药守恒 -> 遮挡/伤害/防具/治疗 -> 死亡尸体；AI须能巡逻、感知、反击、受伤、死亡和被搜刮。
6. **完成一局持久闭环。** 真实出口条件/计时或死亡 -> 唯一终局 -> 账号事务 -> 原生终局/业务结算 -> 大厅 -> 退出重开。所有库存与状态比对一致后才算一局可用。
7. **扩地图、事件与模式。** 任务、地图曼德尔、特殊交互、BOSS、多人与额外地图分别接入。MP部署/复活、占点/得分、载具等按其真实模式另验，不能借单人大坝验收。

各步的最小交付都应包含来源、实际consumer、权威状态、重复/失败语义和一条原客户端操作证据；只完成前两项时保留“调研/协议”状态。

## 7. 验收与下一轮采集

必须至少保留一条撤离、一条死亡/失败，以及事务提交前后断线恢复的完整记录。每条记录关联账号/admission、地图/模式、seed/config、连接代际、实际对象与字段、原始请求摘要、状态前后revision、输出/ACK和最终持久结果。

- 行走、奔跑、体力恢复、蹲趴跳、翻越/水体等逐项动作；时间戳重置、稀疏收包后可恢复，预测不会无限偏离服务器。
- 同干员各可用技能的按下/释放/重复按/取消、耗尽/CD恢复、效果与销毁；死亡或断线不重复扣充能或执行效果。
- 两把实际枪与手部可见；切枪、瞄准、射击/遮挡、换弹/取消、空匣；数量、命中、生命、防具和药品变化一致。
- 真卡/错卡/零耐久、开关/密码/破坏；搜索中断、取物、拆合堆、装备、丢弃重拾；所有GID owner及数量守恒。
- 一个完整普通AI及独立BOSS/特殊兵分支；多人再验敌我、救援、共享物资与全队终局。
- 撤离条件失败/满足、离开取消、收费/开关只提交一次；死亡与倒计时竞争不能形成双终局。
- 提交但delta未ACK、两侧delta已ACK但result未ACK、账号已落库但Settlement未送达分别断线；仅重放结果，不重抽物资、不重复发奖。
- 回大厅和退出重开后逐GID、数量、组件/弹药/绑定/耐久/位置与carry-out一致；旧局消息不得改动新局。

下一轮优先采集范围已经明确：当前 typed FSM h6/identity/子状态；Shift瞬间输入与体力；同次appearance隐藏/挂接原因；真实移动拒绝原因；首次技能RPC的 existing layout/raw slice；真实PackageMap/ActorChannel；源资格齐全的出口/搜索/医疗/射击接收布局。只采缺口，不重复大范围扫对象或强写内部位。

原生测试应在实施相应流程后按已授权的独立 shadow、1800秒及SDK/INI恢复流程运行。本轮没有新增“实机玩法通过”项。

## 8. 本轮复核记录

- 2026-10-20 07:51 UTC统一复核：四份证据JSON可解析，118条顶层来源哈希记录与当时文件一致（包含跨报告重复项），四份报告中46个Markdown文件链接目标存在，脚本AST与新增文本空白检查通过。各分域另记录安装Lua、原生数据节及追加资料的专门核验。
- 只读兼容探针重跑成功：同一真实目录下的无绑定普通物品能通过normalizer；增加明确的绑定字段后被白名单拒绝。测试使用标注的合成本地GID/账号，不写任何存档，不代表所有枪械/物品特征已验证。
- 收尾期间发现协作者更新移动与owner-switch的SourceGuard资格校验。已重新读取，保留原试验哈希及新源码时点；本次观察到的改动没有补充移动纠正、技能/战斗执行或世界权限。后续继续开发后须重新核对来源，不能把本报告当成永久最新状态。
- 本轮仅新增四份研究报告、四份证据JSON、一份只读复核脚本及README研究索引；地图运行源、诊断源、原试验资料和生产账号均未修改。

## 9. 继续追查的新增结果

下列是目录整理期间继续恢复的契约，原始来源、精确行偏移、哈希和脚本均在对应分域报告追加章节。本节更新前述未知项，不将静态恢复计作玩法运行成功。

**六地图静态关联已恢复。** 直接校验原安装257个PAK索引后，完整解析WorldEntrance18行、MapConfig640行、MatchModeDataConfig424行及SubWorld81行，得到：

- `141901103 -> Map1901 -> Forrest_Level1`
- `142201103 -> Map2201 -> Dam_Iris_Level1`
- `143901113 -> Map3901 -> SpaceCenter_Level1`，实际sub11、门卡消耗倍率2。
- `148101103 -> Map8101 -> Brakkesh_Level1`
- `148801103 -> Map8801 -> Tide_Level1`，实际JailBreak规则与子系统。
- `148901103 -> Map8901 -> AZ-5_Level1`，实际AZ规则与子系统。

四个Trials模式的`GameRule14/sub24`也有原表依据。它们都经Iris_Entry入主世界，再按各自SubWorld选择内容。入口表13实际指向76测试地图，不能拿来给Brakkesh；发布board的point_id仍须沿真实服务响应核实。R13N/DefaultPath/热更覆盖的当前选表、各图完整Actor/出口/事件仍需追查。

**field46参数和分派语义已恢复。** 参数是连续位上的presence、6bit行为枚举、presence、可选signed32 SkillID，无字节对齐，合法长度2/8/34/40bits；252组离线fixture通过。派生DFMSkill先过滤behavior21；SkillID>0单个分派，非正ID按SkillStateType1..9查询当前SkillID后逐项分派，不能把省略的0判成无效或当UI槽。保存的8条实际参数可准确解码，但连续可靠ready前缀中没有field46，尚不能证明已按序投递；首次激活30/38和真实task/effect执行仍未闭合。

**代码位置已整理。** 本会话服务端实现现已迁入领域子包，历史函数位置通过旧模块同对象兼容；[结构说明](architecture/SERVER_LAYOUT.md)记录模块位置。07:51的原证据与哈希作为当时快照保留，目录版本另有[整理后重核记录](../work/evidence/gameplay-session-research-20261020-post-layout.json)，不改写原试验文件。

## 10. 调研是否足够：实施范围与剩余证据

结论：**已足够确定接入顺序，并开始有明确边界的实现；尚不足以声明全部玩法契约已恢复或完整游戏可验收。** 以下区分不完整的协议、尚未编写的服务端逻辑与尚未执行的原生验收，避免一直寻找一个能代替全部执行逻辑的客户端配置。

### 本次实际补齐的来源

- **地图选表规则：** [世界报告](GAMEPLAY_WORLD_RESEARCH_20261020.md:218)闭合DefaultPath、R13N及模式专属目录的先后顺序。地区/平台、地区/Base、Common/平台、Common/Base依次探测首个存在项；原安装两张准入表各只有一个Common/Base候选，且没有按match mode替换或组合表。六图静态关联已有原生加载规则支持；当前管理器标志、挂载代际及实际加载表hash仍未采样。
- **技能按键条件：** [角色报告](GAMEPLAY_CHARACTER_RESEARCH_20261020.md:192)确认重复按的guard是有效context、`UsingAbility`及当前SkillID的UserCommand含`Pressed=1`。field38单signed32参数可由通用RPC路径推导1/33bits，但未观察其实际layout/包；field30嵌套参数和31网络parent顺序仍缺证据。field46已恢复的codec不能替代首次激活与效果执行。
- **用药调用与参数：** [战斗报告](GAMEPLAY_COMBAT_RESEARCH_20261020.md:98)补齐健康UI经InventoryManager转发到UseItemManager，再进入RPC wrapper/ProcessEvent的链。请求14为ItemGid、UseItemArgs、ClientAnimTime；请求13为真实取消原因枚举。嵌套字段、部位、来源及结果状态已有声明依据；native结构大小不能当网络长度，实际RepLayout/对象引用/EOF仍待闭合。

### 当前协作者代码的变化

新的[只读快照与探针](../work/evidence/gameplay-session-research-20261020-readiness.json)固定22个地图侧文件及4个大厅侧文件；读取期间逐文件二次检查一致。它独立于07:51与目录整理后的历史JSON。

1. **绑定普通根物品现在可通过normalizer。** 无绑定基线通过，成对绑定字段通过且保留，只有bind_type的半套绑定被拒绝。当前materializer源码还增加枪内弹药绑定校验、删除及写回逻辑。此探针不打开数据库，只验证普通根物品规范化；不能由此推断完整枪械、实际事务、回大厅保存已通过。
2. **移动已增加本地时钟恢复。** `portable_movement_clock_epoch.py`处理符合条件的reset/rebase及一包多条move；各条仍共享原服务器位置/时间预算。runtime启用receive-gap处理，profile明确reset drop2秒、rebase间隔2秒、最大gap120秒及正向rebase开关。这些是显式本地策略，不声称是恢复的官方阈值。
3. **移动已有分类拒绝统计。** 当前MovementDecision有reason_code，11类原因进入per-peer计数，并由control汇总。早先“只有总数”的结论已过时；当前仍缺原生操作对应的时点证据，不能把计数存在当作本次运行无错。
4. **世界安装入口仍未接成。** 新快照中的`install_runtime`仍返回`installed=False`；本局PackageMap、权限、位置资格及真实终局生产者仍是实际缺口。新增移动接受策略尚不是碰撞重演或原生位置纠正。

### 已能开始实现的工作

- 按已有真实ticket/snapshot、实例归属、revision、journal/outbox建立单局状态所有者和持久托管；保留现有终局收据校验、幂等与回读。该生命周期是明确的本地服务端设计，不冒充官方枚举。
- 为已恢复的field46及源推导38编写范围明确的解码/离线测试；38在取得自然layout或精确原始slice前保留未验证状态，不进入假成功发送。按真实模式/干员配置组织task、CD和消耗状态，未知参数继续拒绝。
- 在同一世界账本建立门锁/卡耐久、搜索占用/计时/揭示、取放/尸体所有权、出口条件与唯一终局的状态机。碰撞/导航、AI决策和计时执行需要服务端代码；客户端类、表及UI只提供对应契约和参数，不能自动执行这些规则。

### 必须继续追查或实测的部分

- **协议与客户端前提：** 首次技能30/38及结果31的当前layout/叶子、Pressed消费清空时序、FSM h6及1P挂接原因；开火/命中/换弹/用药的完整serializer和对应消费者；本局静态Actor/PackageMap绑定与坐标转换；当前地图发布board和有效配置。
- **具体玩法参数：** 各技能task/effect、伤害/防具/医疗与取消规则、每类物资搜索、门卡锁关系、不同出口/模式专有规则、AI/BOSS与载具/团队分支。能从真实资源恢复的参数继续恢复；仅有字符串或声明的部分保持未知，不能虚构成官方规则。
- **原生完整流程：** 至少完成一条实际撤离和一条死亡/失败，从输入、服务器判定、物品消耗/产出到回大厅、退出重开及断线恢复。当前没有新增这类通过记录。

这轮研究交付是收窄具体缺口并更新已变化的实现结论。下一步优先完成一个真实技能、一个箱体和一条终局保存流程，再扩展其余玩法；不能以继续扫描更多名称代替这三个可操作流程。

## 11. 继续恢复到参数格式和实际权威函数

本轮继续从原PE不可变声明和已有同版本代码缓存分析，已将多项先前未知恢复为具体契约。以下是新增的研究完成项，均未冒充实际玩法通过。

1. **首次技能30/31/38的标准参数grammar已源闭合。** [角色报告](GAMEPLAY_CHARACTER_RESEARCH_20261020.md:224)追完CppOps标志设置、UHT正向构造后owner头插、函数parent遍历和struct按offset排序。30为skillid、args；args递归13叶，包含三个PackageMap对象引用和三个普通Vector，内部无逐字段presence。31为skillid、ExcuteID；38为单skillid。两个parent都present、三引用null的30共446bits。39段代码复核通过；默认Int32Value1=-1，默认向量从PE loader零填充常量及实际构造拷贝派生为零，未声称采样当前进程常量。具体仍需真实连接PackageMap/profile、自然请求独立对照及权威技能task/effect事务。
2. **医疗14使用参数和13取消格式已恢复。** [医疗报告](GAMEPLAY_COMBAT_RESEARCH_20261020.md:122)确认14三个parent顺序及8个struct叶子，enum宽度、对象引用、bool数组uint16计数与逐元素bool1有具体来源；null目标、三个parent全present时共260+数组元素数bits。13取消参数有1bit省略None或6bit显式Reason两种格式，新增[离线codec](../work/medical_cancel_codec_20261020.py)及6项测试已由本会话重跑通过。它不发包、不取消实际任务、不消耗药品；当前对象资格、医疗任务、结果复制和实机行为继续单独接入。
3. **射击已找到实际自定义serializer与DFM处理器。** [射击补查](GAMEPLAY_WEAPON_WIRE_RESEARCH_20261020.md)从正确RPC getter、实际构造函数与primary vtable追到Fire验证/执行、Hit处理及基类实现。Fire608/Hit208不是网络memcpy：Fire有LightFeature、移动包、条件车辆数据；Hit实际先序列化BulletIndex、普通SpawnLocation与TimeStamp，再进入base，包含7bit FHitResult header、量化位置/法向、对象/FName、速度缩放和条件bit。完整可选分支codec、当前archive上下文和自然报文EOF仍未全部实现；不将结构大小或下游函数存在写成射击成功。
4. **门卡条件和扣除规则已恢复到真实库存调用。** [世界报告](GAMEPLAY_WORLD_RESEARCH_20261020.md:251)经71/72 exec、SOL构造虚表和consume组件绑定实际函数，恢复数量/耐久/GID资格、master-key候选及原门process中的消费时序。普通资格与实际耐久扣除的地图倍率不是同一个公式，失败原子性还需追完。目标动态override、编码坐标、collision/filter和当前对象映射仍须在同一局资格化；不能凭ACK或静态箱坐标授予权限。
5. **付费撤离与合法状态转移已有函数体依据。** 原生先检查局内钱包，再经服务器路径扣费；计时完成经过TrySetCharacterExitState与ProcessCharacterEscaped。SetExitState检查authority、重复/已逃出和迁移矩阵：Normal1、Waiting2、Escaped3、Ready4、InEscaping5各有明确合法边。PS ExitState、MatchOver、业务Settlement和账号落库仍是不同阶段；持续追查它们之间的实际生产和消费连接。
6. **AI行为树启动与实际巡逻编排已恢复。** [AI补查报告](GAMEPLAY_AI_AUTHORITY_RESEARCH_20261020.md)由AAIController/DFMAIController的构造虚表，追到黑板兼容检查、真实组件创建、pending树初始化和节点执行请求。原PAK的BT_Group_Patrol解析147个export、506项属性并交叉校验85个有序child关系；找到AIJob条件、无限循环、巡逻点任务与AdvancedMoveTo共同使用G_WanderCenter的具体配置。23段代码、36段数据和39处指令锚已复验。这不是从远端启动树的RPC；Blueprint任务算法、当前模板选择、导航/感知/攻击及伤害掉落的本地权威执行仍需继续恢复和实施，返回true不保证树实际启动。
7. **死亡/撤离到服务器终局，以及SOL结果发送链已分开定位。** [世界域追加调查](GAMEPLAY_WORLD_RESEARCH_20261020.md)把撤离StateChange与死亡watch追到同一GameplayDelegates、注册回调、延迟ServerGameEnd和OnServerGameEnd。另一条实际SOLPlayer prepare链进入ServerSendSettlementData、SendSettlementInfo和DSLogic发送器，构造pb.SettlementNtf向settlementsvr/SSSettlement发送。关键缺口已收窄到SOL终局回调和结果准备之间的实际汇合：SOL虚表的OnPlayerMatchOver正常体只有hook；另一份完整实现经构造函数核实属于PropHunt，已明确排除。原PAK的DS protobuf声明另确认：DS字段13是`DsQuitGamePlayerStatus.final_props`，业务字段13是`GspQuitGamePlayerStatus.carry_out_props`，二者不能按相同编号直接互换。死亡丢失、安全箱保留和带出投影仍需按真实规则连接，远端settlementsvr的消费/账号事务实现未在该链中取得。不能借用其它模式填成SOL成功，也不能把原生发送通知当成本地SQLite已经提交。

由此不能再笼统说“首次激活、医疗、门卡、撤离都没找到”。标准参数与多项原生规则已有可复核来源；尚未安装的本地执行器和存档连接，需要按这些契约实施并验证。没有来源的分支继续查具体函数/资源，不伪造ID、假成功或客户端不存在的规则。

本会话重跑验证：首次技能39个代码范围通过；医疗取消6项测试通过；射击20份分步查询中的42段代码、135段不可变记录匹配。上述均为离线验证，没有新发包、运行游戏或写生产账号。

## 12. 2026-10-21继续收窄可选格式、AI任务与终局依赖

本节日期采用北京时间。完成的是原安装与同版本缓存的静态复核，未启动游戏、访问进程、发送游戏流量或写账号，也未改动协作者运行代码。

1. **射击格式已有新增的完整分支顺序。** [可选数据报告](GAMEPLAY_WEAPON_OPTIONAL_RESEARCH_20261021.md)恢复FireInfo基类的省略标记、OptionalData的0/1/2/3分支、32位有符号子弹数组头和车辆校验的字段展开。数组上限追到真实`Weapon.Net.MaxBulletArrayNum`配置，原文件初值1000；角度对的16位/32位编码取决于真实`Weapon.Optimize.Net.EnableAimOp`值。车辆分支开头三个bool各占32bits；RigidBodyState与AutonomousFrameData各有一个TimeStamp，均需传输。当前配置、对象/FName上下文、非空子弹元素、FireMove和自然报文对照继续单独闭合，不能把文件初值当成当前会话值。
2. **一个实际AI巡逻任务已恢复到Blueprint脚本。** [巡逻叶节点报告](GAMEPLAY_AI_LEAF_RESEARCH_20261021.md)解析`GetGroupPatrolPoint_C`两个完整函数、62个字段引用和8个CDO selector，恢复对象/类型检查、集合/普通分支、参数与黑板写入、完成结果。普通分支取`GetNextPointConfig`后没有检查返回bool，直接写回并完成任务；因此不能借该任务返回true证明原生选点或移动成功。主原生方法已定位到`0x9eb13d0`并核实成员查找、索引更新、停留时间与姿态读取前段。后续导航/坐标调整、有效AssmblePos默认值和当前实例输入仍待查，其它AI节点没有随之自动完成。
3. **SOL终局hook已明确到指定绑定。** [终局hook报告](GAMEPLAY_TERMINAL_HOOK_RESEARCH_20261021.md)将`OnPlayerMatchOver`收窄到DFMGameplay模块167的stub`0x65af/0x6569`，原名称分别为BS/ES；恢复模块登记、名称表、manager callback和真实Lua函数别名查找。原安装257个PAK中46个指定MetaDorian脚本已核对；Entry优先引用的五个版本不在该PAK集合索引中。这只能形成有界排除，不能证明运行时必定fallback或DS没有其它实现。剩余依赖是同构建实际挂载实现中的这两个stub到Lua alias绑定及其函数主体，或真实DS构建的对应实现；远端账号事务源码仍未取得。

本会话独立重跑：射击11个函数、6个结构声明和11个数据范围与保存证据一致；AI完整重放与保存JSON一致；终局完整重放返回verified。工具、证据与报告链接均保存于各专题报告。这一轮进一步收窄了研究缺口，没有新增完整玩法实机通过项。

## 13. 2026-10-21奔跑、技能、F与地图难度生产流程

本节按用户要求追查生产流程。完成的是原客户端与当前地图checkout的只读对照、调用和配置恢复及离线重放，没有改动协作者生产代码、启动游戏或写账号。具体证据、原始偏移和复核工具在下列专题中。

1. **奔跑已恢复意图生成和服务器消费，尚缺完整权威运动与体力。** [奔跑报告](GAMEPLAY_SPRINT_FLOW_RESEARCH_20261021.md)追到实际输入消费者、Sprint动作的进入/持续/退出、saved move记录及MoveFlags打包。真实mask为`0x4`，接收方从同一位恢复`bWantsToSprint`；它不是“已经在奔跑”的结果。实际SOL移动接收者的构造绑定及逐级分派已核实。当前本地接收器保留raw flags、校验位置与时钟，但未执行这套Sprint/FSM/体力事务。物理按放到具体输入目标、发送端最后一次flags赋值、体力参数/消耗恢复tick/疲劳、碰撞纠正及结果复制仍须闭合，普通奔跑不能借用另一个SuperSprint RPC代替。
2. **技能已按一例串到作者任务和具体运动效果。** [技能报告](GAMEPLAY_SKILL_FLOW_RESEARCH_20261021.md)选原表中的`动力推进/1009001`，连接干员/Expert配置、首次30/31/38协议、状态激活、SkillSubsystem/DataSystem/DFM任务接收者及19个作者任务。HandleRush实际设置movement的Rush意图；结束延迟、Buff、UI使用次数与charging分别有来源。既有connected-v6已经恢复任务接收者，不再保留“接收者完全未找到”的旧结论。但激活到BeginSkill的最终连接、任务调度、真实运动及冷却覆盖优先级仍有缺口，生产收件链也没有技能执行器。SOL基础CD20秒不是当前生效值的证明，原表还有模式、36条地图覆盖和3条标签覆盖；本例也不能替代全部干员技能。
3. **F已恢复输入、长按取消、开箱、逐项搜索和取物的独立阶段。** [F交互报告](GAMEPLAY_F_INTERACTION_RESEARCH_20261021.md)核对原配置`Interact=F`、输入消费者、面板长按/释放，以及实际SOL组件71/72接收与权限链。实际搜索通过选下一物品、按类别/品质算时间、timer、标记当前GID完成、继续下一项或取消；不是所有物品固定3秒，也不是开箱ACK后全部已搜索。取物另走InventoryManager字段45，恢复校验、预/中/后处理、移除/增加、容量与数量边界；恰好取完整堆会扣到零。物理委托到面板、Blueprint条件、实际锁和位置、部分堆叠及完整复制提交仍未闭合。
4. **更正世界运行时的当前状态。** 当前有manifest时，`install_runtime`已可返回`installed=True`并安装`RegisteredBoxReceiptRuntime`，因此第1节的笼统`installed=False`只代表旧审查时点。但当前收据运行时仍明确`mutation_ready=False`，缺真实箱体世界位置和交互许可提供器；没有manifest的分支仍拒绝安装。现有本地策略只允许合格的immediate-open及有界整实例转移，未接齐上述原版搜索timer与任意取物流程。对象收据接入不能作为权限或物品变更成功。
5. **六图的实际档位组合、世界关联与缺失响应已核实。** [地图难度报告](GAMEPLAY_MAP_DIFFICULTY_RESEARCH_20261021.md)完整读取Map640行、MatchMode424行、WorldEntrance18行、SubWorld81行，按真实MapID与世界名关联。六地图族共82条模式，其中32条属于SOL的10/11/12基线集合，包含单人、训练与区域变体，不能全部发布。主要三人组合为：长弓/大坝`10、11`，航天`11、12`，巴克什/监狱`10、11、12`，AZ-5`10、11`。这些是该安装的静态配置，不证明当前全部开放。[枚举定义](GAMEPLAY_MAP_ENUM_RESEARCH_20261021.md)由原`ds_common_pb.lua`实际赋值闭合，未按ID位数猜测；独立业务字段`difficulty`不是这套10/11/12，官方发布值和本地化对应仍待补证。
6. **难度缺失并非只少按钮。** 当前默认发布目录两条均为大坝`Map2201/mode142201103/sub10`，只是match_mode_type不同；响应构建未显式填独立`difficulty`，门票、装备和携带限制等也未完整构造。原客户端按point、submode、mode type及独立difficulty分类，再读取等级、门票和装备条件。入局还必须固定对应SubWorld、规则、时长、门卡耐久倍率、任务、出生、物资、AI、撤离并沿用到重连与结算。其它图point、动态开放和准入值不能由现有大坝值复制。环境变量可替换默认目录，本轮未读取运行进程环境，不将默认文件宣称为所有实机响应。

独立复核已完成：奔跑当前快照53项匹配；动力推进175个来源pin与11个函数匹配；F的94段native、330项unwind、13项不可变记录、9个源码pin、8个原资源包及边界证据通过；地图关联和枚举完整重放匹配。协作者期间更新了3个启动/来源校验文件，旧快照已保留，奔跑和技能另存reaudit证据后重新通过，具体记录见专题尾部。上述是已完成的调研与离线验证，不是四项玩法已修复或实机验收。

## 14. 2026-10-21继续恢复规则输入与实际分发

本轮接上第13节的具体未知项，继续只读原安装、冻结代码缓存和协作者来源。没有修改生产玩法模块、启动游戏或写账号；新增研究工具和证据均放在本仓库对应专题内，旧证据保留。

1. **独立地图难度已有真实定义与消费连接。** [难度语义补查](GAMEPLAY_MAP_DIFFICULTY_MAPPING_20261021.md)逐项核验原索引5701个Lua chunk后，找到RecruitConfig的实际赋值：`1=常规行动、2=机密行动、3=绝密行动`，并显式映射到`SOLPMC10 / HighYieldSOLPMC11 / ExtremeHighYieldSOLPMC12`。ArmedForceConfig的独立文字表一致；RecruitLogic实际把board难度键与targetId比较，再用该映射查真实match_mode_id。这更新第13节对显示语义的未知项，但仍不证明当前官方board开放值、门票/装备门槛或所有入口已发布。每图主要组合现可按来源标成：长弓/大坝常规与机密，航天机密与绝密，巴克什/监狱三档，AZ-5常规与机密。
2. **Sprint体力从请求、持续tick推进到具体默认配置。** [体力调用补查](GAMEPLAY_SPRINT_STAMINA_RESEARCH_20261021.md)固定SprintPenalty真实type18、DeltaSeconds与ChangeCount参数，区别16B独立变更配置与4B持续变更配置；常规Sprint分支按tick delta、DurationValue和动态StaminaSprintChangeRate计算候选。[默认组件配置](GAMEPLAY_SPRINT_STAMINA_CONFIG_RESEARCH_20261021.md)通过BP_DFMCharacter_C实际引用的GPStaminaData导出及唯一原PAK资产，恢复Sprint系数-3、SuperSprint -20、SwimmingSprint -5、Normal/StandRun +4.5、Penalty即时系数-1和恢复等待配置1.5。这些是明确CDO配置值，不能把动态倍率默认为1或将某一分支当成完整体力公式。
3. **重复启动惩罚的启用前提与负重曲线已补证。** [策略输入补查](GAMEPLAY_SPRINT_STAMINA_POLICY_RESEARCH_20261021.md)从确切global指针追到`Sprint.ConsecutiveSprintPenaltyDuration`注册默认float1.0，以及独立开关`Sprint.ConsecutiveSprintPenalty`注册默认0；消费者确实在开关为零时退出。当前有效覆盖未观察，不能按配置行存在直接启用惩罚。组件所指负重曲线也已按精确资产恢复两个线性键，第一键保留原始微小浮点值；输入轴如何由负重换算和参与完整公式仍待恢复，未按名字猜比例。
4. **F输入管理器到面板已有直接静态分发，并纠正旧owner误判。** [F分发补查](GAMEPLAY_F_DISPATCH_RESEARCH_20261021.md)恢复Interact注册、按放动作0x8f/0x90、队列、二级表、实际DFHDInputManager虚表及面板反射exec，接到DoInteract1KeyPressed/Released。模式和HUD状态条件保留；它不是某次当前实例已选中该路径的观察。旧报告将`0x32e4000`叫作HUD广播有误：GetBaseHUD仅作非空gate，实际另取得GPGameplayDelegates并于`0x4e1120d`调用广播。该GP对象+648与新链的DFMGameplayDelegates+1fa8/+1fb8不能混接。首次搜索进一步收窄到角色SetIsLooting分支；BoxFinish到该状态的产生仍不由收据证明。

   [目标组件接收者补查](GAMEPLAY_F_RECEIVER_RESEARCH_20261021.md)进一步从PotentialInteractorInfo/InteractableProxy反射布局和缓存写入限定`panel+518`为目标侧DFInteractableComponentBase，而非角色侧SOLInteractor。其基类OnLocalExecute fallback查找角色组件，再有条件进入ExecuteInteractableCompByTag。历史同版本ClassNetCache确认实际SOL字段为**70**，exclusive maximum168，参数是目标组件/tag/context；不是Actor版71或InteractAction72。当前`portable_world_interact_request.decode_field`第166行只接受71/72，`portable_world_loot_dispatch.interact_field`第141行调用它，因此这条解码路径明确漏接组件版70。两份源码与历史元数据已固定；不能扩大成所有运行路径均缺失，也不能将72B原生参数结构memcpy为线格式。field70的FunctionRepLayout、当前组件引用和具体override仍须补证。
5. **技能已区分实际DataSystem入口、命令表与状态监听表。** [首次激活补查](GAMEPLAY_SKILL_ACTIVATION_RESEARCH_20261021.md)纠正`0x32e4160`为DataSystem getter，不能叫charging getter。普通command0已接到SkillBehaviorMap；作者BeginSkill task监听的byte1查询另一组表。后者的登记、DataSystem ConsumeCommand_BS、template构造虚表及实际EnterLogic/任务分发已有来源，但首次状态提交如何产生或消费该byte1仍未闭合。不能将普通命令和状态监听两路拼成完整首次释放。
6. **技能CD哨兵和复用条件已明确。** 同一补查证明`-1.0`走非正时间分支，读取slot配置和可能的owner倍率，特定旧timer分支可使用剩余时间；新timer复用判断发生在数量修改之后。因此“没有新建倒计时”不证明重复task幂等，也不能统一填当前CD20秒。实际mode/map/tag选行、首次释放资格、任务运行策略及最终事务继续分开闭合。

本会话已独立重跑新证据：体力调用71项、默认配置1052项、策略输入1081项全部匹配；F分发65段native、146项unwind、22条直接分支、34条指令、6个指针和2条动作路由通过；F目标接收者57段native、103项unwind、24项不可变记录及字段70身份、参数类型、两份consumer源码检查通过；首次技能38个连续函数、14个来源pin和9个有类型绑定匹配；难度定义五个原chunk与5701-chunk内容检索重放通过。旧报告中F广播owner和技能getter的错误称谓已明确勘误，来源哈希匹配本身不能替代语义审查。上述新增项仍未作为生产玩法或原生实机验收。
