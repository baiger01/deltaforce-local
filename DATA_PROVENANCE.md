# 数据从哪里来

## 仓库十级容量与扩容箱（2026-10-20）

完整十级 `SafeHouseUpgrade` 行已核验，不按截图中单个等级补丁处理。
`native-warehouse-text-contract-20261020.json` 保存原客户端已加载的 42 个字段，
经 `FText+24 -> 引用+40 -> 条目+32 -> FString` 及原生访问器指令验证显示文本，
排除相邻字符串。仓库 1 至 10 级累计增加行为 0/2/2/5/5/8/8/12/12/16，
对应 0/18/18/45/45/72/72/108/108/144 格；箱槽为 0/1/2/3/4/5/6/7/8/9。
升级取当前已完成等级的效果，不累加旧档位，不提前使用倒计时目标等级。
用户提供的原生解锁预览截图 SHA-256 为
`587e45ebd3e5ceb4f8dce243e8bd7df70c74ae42a09f9fc526fc3f112fe73ece`。

基础 315 格另有明确限制：原始 PC 创作者报告十级总容量 459，原生升级画面为
累计增加 144，据此推导 `459-144=315`，并非恢复官方一级账号响应。
`native_warehouse_growth_catalog.json` 保留来源、平台、未知版本和无额外容量奖励假设。
新账号显式记录该推导策略；旧无台账账号保留 9x40，只有独立备份迁移才调整。
本账号迁移已完整备份并重排 105 件、225 格物品，核验实例、数量、组件、货币、任务
及其它受保护表不变；记录见 `warehouse-geometry-migration-20261020.json`。
旧库备份 SHA-256 为 `0a45520cf488e0b157d45861e5c4fb79863e34940a6d20e2b0f834092c9ffa9e`。

`ExtensionBoxDesc` 原导出 entry6520，SHA-256
`e20998feb112b48fbefebdae9f4ee185c04aea9a4c92a2b67dec32d6d1d05876`；20 列反射绑定、30 行逐项内容见
`native_extension_box_catalog.json`。真实箱内行列和允许前缀、排除类型、排除品质
用于安装、物品存取和整理；未恢复的专用/VIP 路径不授予权限。
普通扩展页从 3 开始，装备槽为 `page*1000+1`，顺序保存槽 ID 而非页 ID。
空箱卸载保存原实例；已安装箱不能经出售、任务提交、生产交料或普通移动直接删除。

原安装回调不应用库存变化，服务端先发送实际库存通知再返回回调。
原通知会无条件覆盖扩展顺序，所有库存通知出口均附真实已保存顺序；未变化的数量
显式为 -1，真实零值保留。连接内比较基准来自实际发送的回包，避免并发升级被漏报。
原始调用证据见 `native-warehouse-callback-contract-20261020.json`。

普通 `_OnCSDepositEquipPropRes` 同样无条件设置扩展顺序；其成功响应现从本次
移动事务捕获 `extension_pos_order`，提交后才发布，失败不发布回执。
缺失顺序会将箱页选择误导到钓鱼仓库 97，触发 `97001` 空物品标题断言；
完整调用、原 Lua 哈希及实际日志见 `native-warehouse-title-failure-contract-20261020.json`。
原 `ItemSlot.InitSingleSpaceStructure` 使用空间编号 1，主仓库和普通箱页接受真实 1
及旧协议兼容 0，仍拒绝其它未恢复空间。2026-10-20 用户确认物品存取和箱页重开正常。

## 分堆、装弹预算与空收藏已读（2026-10-20）

原 `ItemOperaTool.DoSplitItem` 将用户选择数量交给普通移动；`199997` 是原协议
`eEquipPosition.Pocket`，不是临时槽。原导出物品 `37300600001` 为 1x1、每栈 20。
本地部分移动保留原栈 gid、余量和绑定，新栈使用本地实例 gid；真实原生请求经
加密分发回归验证数量守恒，失败整事务回滚，未修改生产账号数据来规避错误。

`native-bullet-contract-20261020.json` 核验原 `ItemOperaTool` 和 `GunsmithAmmoLogic`：
普通拖拽传弹堆数量，虚拟记账采用 `min(已装+请求,容量)`；快速配置另有先卸再装链。
实际日志的两枪已装 5/5 和 30/30，原表及已安装弹匣容量一致。
本地按剩余空位截实际增装、满匣成功零转移，不隐式卸弹、换弹或扣除多余弹药。
这是原客户端请求契约上的本地处理策略，未恢复官方服务器满匣异弹种行为；
拥有数量、口径、归属及未知容量校验仍保留。

`native-collection-empty-read-contract-20261020.json` 核验原 `CollectionLogic.RemoveRedDots`
和 `CollectionServer.UpdateRedDot`：原 helper 会发送空身份条目，成功回调无红点记录则跳过。
只将 `props` 中 id/gid 均缺失或为零的条目作为空操作，仍鉴权；未知非零 ID、错误 gid
及零 ID 搭配非零 gid 保持整批拒绝。不为占位条目创建物品、归属或已读记录。

## 现金条件与枪械提交候选（2026-10-20）

原 `QuestStruct.lua` 0.8 仅将 Type1 Submit 加入 `_submitObjectiveList`；
Type2 Currency 不进入手动提交，`QuestDetailView` 0.21 只使用该物品列表。
原五条现金目标 4900101 至 4900501 的 Param1 均为 17020000010，要求依次为
500000、2000000、10000000、25000000、50000000，无额外条件。
旧本地扣款提交语义已移除，改为按已登录账号实际钱包更新 Accepted 任务的条件。
接受、任务查询和交易成功后刷新，完成与领奖分开，不创建实体现金道具。
事务通知在写入后发送；后续余额同步失败记录错误，保留已完成的交易，后续查询可重试。
余额比较及完成状态保留是明确的本地重建，未恢复官方远端判定／锁定代码。
可重跑调查入口 `work/research_native_quest_cash_20261020.py`；报告
`work/evidence/native-quest-cash-contract-20261020.json` 保留 12 个原数据与 Lua 哈希、
函数、指令，以及只读检查的钱包 100284911 与旧任务进度 0 的实际差异。

原任务 50001 只有目标 5000101，要求枪体 18010000010 及配件 13110000044 一把。
`QuestLogic` 0.17 按实际拥有的枪生成候选；原 `ItemsSubmitPanel` 0.9/0.12
分别显示需求和候选，0.10 在目标达到 1/1 后关闭整个面板。
面板中其它条目消失不能证明多扣库存；两把合格枪的回归验证只消耗选中的一把，
另一把及其配件保持不变。源面板 PAK1 entry 4298，条目 entry 4297；完整哈希与
11 份指令见 `native-quest-submission-candidates-contract-20261020.json`。

## 行动经验与声望等级（2026-10-20）

`native_action_level_catalog.json` 从 SeasonLevel 原始序列化导出读取 60 行，
PAK2 entry 7084、偏移 50371705，SHA-256
`16389ea97f300742cd11bf3e346f5480ac94dbf9b7549865ea8a1a8c8505bac9`。
原反射注册偏移 489442048、描述符 413285552；Level 为 int32、Experience 为 FString。
GrowthRoadServer.lua 0.15 返回当前行 Experience 作为下一级消耗，0.22 以 0 识别终点；
SOLPathOfGrowthLevelUpPanel.lua 0.13 使用级内经验。提取入口
`work/extract_native_action_level_catalog.py` 支持重新提取校验，未生成原表空白的等级奖励。
经验模板为原 EXP_ID=26010000001，原通知 source=season(0)，只生成 change 分支。
任务发奖、经验账、行动等级、材料及声望在同一事务保存，原生通知提交后发送。
没有历史经验明细的旧档保留原行动等级，以该等级下限建立明确审计的本地基线，
baseline 与真实 earned_exp 分列保存；不伪造已赚取的历史经验。

原 RoleInfoServer.lua 0.13.0 分别覆盖行动、账号、爆破字段，省略独立字段会读取协议默认。
旧本地实现曾把一份等级投射到三套字段。`native_lobby_independent_level_baselines`
在首次查询或行动发奖前记录该旧展示值及原因，此后行动经验不再提高账号／爆破等级。
这是本地兼容策略，不是恢复官方账号／爆破经验曲线，也不发放这两类经验。

声望宽度另存 `native_reputation_curve.json`，SHA-256
`ef54e863259e1a8c5568cf522660e32882538846ab10aef7f1d910bcd834b414`。
LV2 的 2/30 来自原始玩家视频 `https://www.taptap.cn/moment/633848456032554940`，
LV3 的 14/30、12/30 来自原始作者 `https://www.youtube.com/watch?v=fnAzODg7Jho`。
LV4 MAX 有五部门原版截图，截图、帧时间和哈希逐项记录在文件中。
LV1 的 20 来自 K4 自有服务目录明确的经验值列
`https://k4dianjing.com/sanjiaozhou/dailian/bumen/`，另保留原始报价和作者记录交叉印证。
第一档未观察到原版数字弹窗，提供者页的客户端平台／版本不确定；整表明确标记为
`native_observations_and_primary_report_inference`，不是恢复的官方服务端响应。
终点 score 未知，记录为 null 并在协议中省略；只确定最高等级 4，不虚构终点分数。

## 放弃任务与设施能力查询（2026-10-20）

原 `QuestServer` 0.35/0.35.0 使用 `CSQuestGiveUpReq.remove_quest_id`，响应成功字段为
`CSQuestGiveUpRes.res`，不是其它任务接口的 `result`。`QuestStruct` 0.21 将接受时间清零，
回到 Unaccepted 并重置目标；`QuestObjectiveStruct` 0.5 只清数量和完成标记，保留跟踪、
用时和选择字段。`QuestDetailPanel` 0.11 限制为 Accepted 且非 ShouldAutoAccept；
`QuestConfig` 明确告知提交物品不返还。原行、函数、偏移与完整哈希由
`work/research_native_quest_abandon_20261020.py` 重新读取生成。普通 Mission/Branch
按这条通道处理，匹配中的客户端按钮拒绝仍由原版界面执行，未捏造服务端匹配状态。

`InventoryServer_Network.lua` SHA-256
`d7f83db2ae2cf4902b440131c15648c7b7d4b8b8f5e459231b9eb6ec17dcb0dc`，
0.8 偏移 10974 请求 SU_DepositRepair，0.8.0 偏移 11147 指令 15 至 20 只比较返回
unlock_id 就开启维修能力，不检查内部 params。旧静态查询因此会误授予未获得能力。
原 common_pb 指令 2239 至 2279 给出 SU_DepositRepair=15，唯一原表授予是
SafeHouseUpgrade row14、偏移 8357，设施 1011 完成二级后的 `21:2;15:2`。
新查询只返回当前已完成等级产生的条目，未知或未获得 ID 返回外层空列表。
复合参数保留源 colon 元组，各已完成等级分别输出，不猜测相加或末项覆盖规则。
完整原版逐文件重读与协议字段核对见 `work/evidence/native-safehouse-unlock-contract-20261020.json`。

## 设施进度与旧存档迁移（2026-10-19）

`native_safehouse_progress.py` 使用已恢复的 73 条 `SafeHouseUpgrade` 原始行。
PAK entry 7072、偏移 50353481，SHA-256
`a512e06581e890beccbc03d57fac4960d53647b0f2a0f14e1e5078f0a9a6def2`。
`BlackSiteServer.lua` SHA-256
`69389419f7b0fb5e3b993c2e65fa2b46f659e3e50c3cf2f375d94d519f6ae890`，
0.10/0.11 分别使用 `CSSafehouseSubmitUpgradePropReq` 和 `CSSafehouseUpgradeReq`。
提交实际物品实例，升级另扣货币；材料、等级、起止时间与完成历史分别持久化。

`BlackSiteDevice.lua` SHA-256
`d1a05e46806f6498e8d680f4838d5b443b24cc821cf8337e591ea73deec5aa1b`，
0.4/0.28 核对等级、设施、声望与任务条件；0.63 区分货币和可分次提交的材料。
0.52 偏移 26852 与 `BlackSiteLogic` 0.21 偏移 12248 确认
`UnlockSystemList` 是已完成等级产生的功能，不是建造条件。
0.58 偏移 29525 的升级判断没有生产线限制，二者保留独立计时。
`BlackSiteConditions` 0.10 偏移 8348 使用 `bindType=-1`，0.11.0 偏移 9883
对未绑定材料额外提示，未将可提交材料错误限制为单一绑定类型。

官方新账号设施初始化未恢复。本地只自动完成原表无材料、无前置门槛、行动等级不大于 1、
时间为 0 的首级；其它设施缺少保存行时下发 0 级，不能把它们全部设为 1 级。
保留账号的旧十项等级恰与 `safehouse_max_level_candidates.json` 相同，其中
1003、1014、1017 超出当前原表上限。显式迁移只接受这个完整指纹，拒绝已有真实进度，
并检查除设施等级和迁移审计外的全部原表数据不变；没有缩减仓库几何或删除库存。
2026-10-19 10:21 UTC 完整 SQLite 备份 SHA-256 为
`ba71fdf34464b18cc125006e41b6d76b9e84fd988e4bdac0e568f78602d3e876`，迁移已提交。

等级型任务来自原 `QuestObjectiveType`：ReputationLevel=21，Param1 为真实声望卡 ID，
RequiredCount 为目标等级；UpgradeSafehouseDeviceLevel=6，Param1 为设施 ID，Param2
等于 RequiredCount。18 条声望目标、14 条设施目标及 16 份 Lua 哈希见可重跑的
`work/research_native_quest_standing_20261019.py`。客户端复制服务端目标值和完成标记，
官方服务端判定代码未恢复；以本账号持久化等级比较要求，是明确的本地重建规则。

五个商人 ID 已由源目录连接核实。安装版 `ShopServer.lua` entry 6940、偏移 35084288，
SHA-256 `4fe3e3b9cfcbc414503a5b2672b93c9b78f07b0837834f12759b1568e4908325`，
0.55.0 按源 MerchantID 保存响应；`MerchantStruct.lua` entry 1846、偏移 8589312，
SHA-256 `33c211cc7f934d84c5698a9c7d7f10e36b92528ca6016c3a02ba2f46a9b6100f`，
0.6 独立读取 RoleQuality.level。common_pb 根指令 7741 至 7754 将 VIP、好感等字段
默认为 0；无依据使用旧固定 VIP 1，因此五条响应只给真实 id，未把声望复制到 VIP。

## 部门任务与完成配置（2026-10-19）

`work/extract_native_quest_objectives.py` 从安装包 PAK2 的 entry 6938、文件头偏移
`49951385` 读取完整原始导出，SHA-256 为
`28cf6ef592faacd18f5ddcfed62dc5a86ec433dcf44cc4f529857149f2168c49`。
同版本 PE SHA-256 为 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。
`QuestObjectiveRow` 注册位于 PE 偏移 `489434912`，31 个有效字段与偏移 `413646960`
开始的完整原生描述符逐列对应，内层数组属性及枚举 UnderlyingType 不作为顶层字段。
全部 4537 行通过序列化顺序、类型、宽度、布尔元数据、数组计数和末尾标记校验，
2365 条已恢复任务引用的目标缺失数为 0。输出为 `protocol/native_quest_objectives.json`。

原 `common_pb.lua` SHA-256 为 `81e071e35f33f0e5704d5098ac2a182c794bbe5b1e5a7e24f415a0473b40350b`。
`QuestObjectiveType`、`QuestRewardType` 直接读取根函数的 LOADK／SETTABLE 指令，
包括 Submit=1、Currency=2、RewardQualityValue=4；没有从物品号或名称推测枚举。
`QuestServer.lua` SHA-256 为 `66923c74fb9516e33c5e50676b422bfc4183b3604b4b0d4947cb38dc9f97881c`，
函数 0.31、0.32、0.33 分别证实完成、领奖及按 obj_id 提交 submit_props 的不同请求。

本地完成配置是用户明确要求的测试功能，默认关闭。只采用原表 QuestID、ObjectiveID
和 RequiredCount，保存 Completed，与 Rewarded 分开；不自动扣料、发奖或改变声望。
最初状态另存 `native_lobby_quest_completion_overrides`，失败时随任务记录一起回滚，
通知在提交后发布。测试使用临时数据库，没有对保留的测试账号执行全任务完成。

部门调查发现 `RoleInfoServer.lua`（PAK1 偏移 `34949120`，SHA-256
`a6221ddd4f16c4c77be62be552b78eb275f06f9710aed57c3ec529e543eb7503`）
函数 0.58.0 读取服务器 rep_level_configs，函数 0.69 返回该数组长度作为最高等级。
旧通用空响应使其长度为 0，`QuestServer` 0.43 的满级比较因而出现错误。
原 RoleQuality 表确实存在，但其 14 列不包含等级分数阈值。2026-10-20 已接入上述
原版界面和明确标记的提供者记录重建曲线，官方 RepLevelConfig 原始响应仍未恢复。

## 原生任务提交、奖励与绑定（2026-10-19）

`native_department_catalog.json` 保留 8 条原 RoleQuality 行，以及由原
BlackSiteConfig 显式字典、QuestLine 和两版 TraderInfo 交叉核对的 5 个活动部门。
309 条 Type4 奖励上下文以 QuestID、RewardID、任务线和部门关联；这是有源行偏移的
关系连接，不是物品尾号规则，也不是声称恢复了 ItemUse 效果表。
29 条没有活动任务线祖先的上下文保留为未解析，领奖时整笔拒绝，避免发错部门声望。
可复现入口为 `work/extract_native_department_catalog.py`，原 PAK 哈希和每行偏移在目录内。

物品绑定枚举直接来自同版 common_pb 根指令 512 至 520，取值为 0/1/2。
`ItemBase.lua` SHA-256 为 `5361e9a383ca5f3a2b675704e464b414f4a4631f10d28e4798821eba2097e837`，
构造函数 0.2 指令 13 至 14 设置省略绑定字段时的初值 (1,0)，
SetRawPropInfo 0.12 指令 28 至 37 读取 PropInfo 的真实绑定字段；没有把所有购买推定为绑定物品。
新奖励保存原 RewardRow.bindType，物理与装填弹药分别保留绑定元数据，拆分和合堆遵守它。
同文件 _LoadItemInfo 0.11 指令 151 至 160 明确将 maxStackCount=0 归一为 1。

改装枪提交还要求原 Objective.ListParam 的每项配件都存在于实际保存的枪树。
`WeaponRestrictionsComponent.lua`（PAK1 entry 4299，偏移 21000192，SHA-256
`fa82c72d5c056cf5769907f2123e935972f7900fd57eaed87d5000f3cbcbef3f`）
函数 0.6 指令 112 至 156 为每个配件创建限制项，0.6.2 汇总所有项的满足状态。
`QuestObjectiveCompoDesc.lua`（entry 5189，偏移 25286656，SHA-256
`17d408d5365d95376f95b1e65a06a8e18fef91f0ae37c21081e9dc72c0743555`）
函数 0.5 指令 93 至 107 按单个配件检查实际枪体。
`GunsmithMissionLogic.lua`（entry 3794，偏移 18571264，SHA-256
`95b611e812944dec73985a4c88ef6a479449d50d25bbf91cfda3dd7a34075ebd`）
函数 0.8 指令 16 至 47 从真实描述对象的 SocketGUID→ID 字典判断是否装配。
这些消费者的原指令与哈希已一并加入目标目录；请求中伪造配件预览不能代替实际库存装配。

`native_quest_weapon_presets_catalog.json` 从原 GunPreset 的完整节点树恢复普通任务
使用的 42 种武器预设。源 entry 4567，SHA-256 为
`0075368148ad3c2ffcaec020bfee36b1ac0bacd13506af1502c744ada5b137b5`。
例如任务 11001 的奖励预设 10010001050 实际枪体是 18010000031，
不能用同枪种默认预设替代；奖励落库时即保存该预设的真实完整配件树。
原节点偏移、父子槽位校验和提取入口均保存在目录和 `work/extract_native_quest_weapon_presets.py`。

经验模板 26010000001 来自 DFMGlobalConst.lua 的 EXP_ID，哈希与根指令保存在目标目录。
2026-10-20 已按上述原 SeasonLevel 表接通实际经验入账、行动升级及原生经验通知。
奖励事务内写入物品、货币、经验、部门声望及逐奖励行收据，再将任务改为 Rewarded；
任何部分失败会全部回滚。成功后才发送原生库存、收藏、任务及已恢复干员外观通知。

## 礼包收费条目购买修正（2026-10-05）

03:53:45 的实际 `CSShopBuyHotRecommendationReq`，序号 472、tab `10101048`、`banner_type=1`，只提交 `28040250003`、`28020250006`、`28060850003`，报价 2400，旧响应为 `14026`。推荐原表 row 138、偏移 `230736` 的三件收费皮肤分别原价 1150、折扣价 800，另有四件零价赠品 `13460040218`、`42010040740`、`42020030782`、`38020030561`。旧代码用所有七件配方长度判断整包，误将三件收费条目按单件原价核算。

原 `RecommendBuyPacks.lua` SHA-256 为 `7fe3ba6e80957288a742e4ca43eedcfba99737a7ff5bc92a5a90f932554b904d`；函数 `0.21`（偏移 `17095`）指令 33～35 在剩余收费条目不超过一件时使用原价，函数 `0.7` 的指令 14～24 保留单件独立购买。`StoreServer.lua` SHA-256 为 `71987b0e506b13d19e57e813f64e09552482df76a17fe94302d91149f7d44d0e`，函数 `0.145`（偏移 `103224`）原样转发条目和报价。修正以实际归属和原配方识别完整剩余收费集合，整包一并保存未拥有赠品；显式单件仍按原价独立成交，不能冒用折扣或单领赠品。138 条开放推荐的折扣总和与原整包价格逐条一致。

新增回归覆盖实际三件请求按 2400 成交、剩余两件按 1600 成交、最后一件按原价、独立购买后免费领取剩余赠品，以及全部发货后发生错误时恢复货币、收藏与购买记录。37 项商城用例及 74 项关联联合回归通过。04:24 原客户端试验记录五次礼包购买成功（序号 481、508、579、591、623），包含整包、单件及剩余赠品领取；原序号 472 的三件向量未在本轮重新发送，不将其它成功请求当作该向量的实机复测。

五次成功请求均对应存档的新购买记录 23～27。序号 508 的 tab `10102053` 购买三件收费枪皮肤与四件赠品，报价 2400 对应原 row 120、偏移 `195550` 的三件折扣价 800；序号 579 单买 tab `10104005` 的服装 `30000050017`，2210 对应 row 74、偏移 `118890` 的原单件价。序号 481、591、623 的收费项此前已持有，本次分别补四件、七件展开后的赠品、四件赠品，不作为新的付费购买计数。枪皮肤检查独立枪皮归属，服装检查收藏归属，未将装备状态当作获得奖励的依据；四个礼包的完整配方物品均已拥有。

同轮 04:26:03 的 `ConnectionResetError` 出现在 `/api/local/native-identity` 的响应头发送；旧异常处理误将已执行的请求标记为内部错误，再次发送 500 又失败。`http_api.py` 仅在发送层处理连接重置、管道关闭及连接中止，保持业务异常处理与已提交状态。新增用例验证响应头、正文及错误响应的断连不会重新执行业务，普通发送异常和真实业务异常仍按原处理；57 项 HTTP、身份及商城联合回归通过（20.247 秒）。

## 全量礼包资源核对（2026-10-05）

`work/bundle_catalog_audit.py` 逐项核对全部 158 条推荐和 61 条特供。推荐表来自基础 `pak-0-0-pakchunk2-WindowsClient.pak` 条目 7142，头偏移 `50505481`，解码 SHA-256 `bcf064ebee25d046e21712375adf8e68f80b71bedd9c5c65f1fcb6a6d771a1fc`；特供条目 7156，头偏移 `50554393`，解码 SHA-256 `1b7640b1121e61e9fef64a8f986f5620588fb1e9a70822f8feae9898056b68d7`。提取器保留推荐字段 271／273／275 的大图、小图、Logo，字段 281 的物品排序；特供字段 80／87 保留横幅与排序。字段 304 的 11 个资源引用保留原文，角色未知，不擅自作为另一种图片绑定。

[完整资源清单](outputs/df-local-server/protocol/premium_shop_resources.json) 包含全部 219 行、1325 个字段槽，明确区分原表空值、实际缓存和未核实包归属；其中 504 个本地引用对应 497 个不同虚拟包路径。原生大图等信息由客户端本地表读取，新增审计字段没有作为未经确认的协议字段下发。`StoreRecommendItem.lua` 的 `RefreshServerInfo` 将协议的 `IamgeSourceSmall_CDN/IamgeSourceBig_CDN` 写入内部 `ImageSourceSmall_CDN/ImageSourceBig_CDN`，协议中的原始拼写保留。

本机只读核对的商城缓存位于 shadow 的 `DeltaForce/Saved/Cdn/G/CN/Resource/Store/`。初始快照的 47 个文件全部能对应源表；48 个含 CDN 的推荐中，18 个至少有一个缓存，30 个没有对应商城缓存。这不是资源不存在的判定。这份快照的缓存名变换最初只由 47 个文件的数学对应支持，随后原生实现已单独核验，见下文；快照数量不冒称当前缓存总数。源路径后的扩展名不擅自增删。26 个含 PNG 签名的文件是客户端专用序列化格式，其 offset 40 的 Oodle 数据按原头长度有界解压成功；没有将它们当普通 PNG 损坏，也没有替换图片。像素格式、原生纹理创建和最终渲染尚未核验。

`work/bundle_asset_locations_media.py` 完整解析三个保留的 `MediaResTable` 导出（各 799 行）和 196 行 `ThemeBackgroundData`。23 条媒体行的纹理对象与礼包图片精确相同；关联礼包的 13 个现存视频文件大小与源表一致。96 条推荐与背景表有确切物品 ID 交集，保留场景路径及行偏移；该交集不能代替原生礼包到主题的选择字段。选用的媒体表由显式文件参数决定，不按文件名排序冒称当前加载版本。公开清单仅含来源哈希、路径和状态，不包含原始图片、游戏资源、账户、日志或本机绝对路径。

`work/bundle_reward_resources.py` 另行生成[奖励资源清单](outputs/df-local-server/protocol/premium_shop_reward_resources.json)，覆盖全部 219 行的 1115 个直接奖励条目；17 行原本没有直接奖励，仍保留。武器皮肤原条目 7292、SHA-256 `03929c8c36ef4bd21de0e6262809095a863f3e65d6e44e8eefcf6ac57a59cce7` 的字段 1823 在 110 个奖励皮肤行中有 38 个不同文件名，涉及 39 行推荐／特供。这些值只有原始 `C=...jpg` 文件名，没有目录；字段角色和原生消费者未恢复，不擅自加 `Resource/Store/` 前缀。原 GameItem 另有 3 个非空奖励图标；空 `MallItemIcon` 不能代替客户端按类别选择图标的判定。

11 个奖励外观 ID 与 `CharacterAvatarData` 原行精确相同，9 行礼包涉及 54 个不同 UI／TPP／FPP 网格路径。原头像表头／内容 SHA-256 分别为 `fd3dea4bda6dbb41cf354e9cbf7b527c53e1e8b0081bbb0c5dafdf8460a1e496`／`336a7c5af693b6190e630e5360367a8129b3a426fdfc95319b2cbfbeda38e6b3`。`CharacterCaptureUtil.lua` 来自 PAK1 头偏移 `15683584`，SHA-256 `db1259fcaea601cc57d027cc8651f34709059efc11f867a63cc47defd7efdac6`；函数 `0.28`（偏移 `18133`，501～555）在 `WarehouseMain && IsShowFashion` 分支将当前外观 ID 传给 `SetAvatarByFString`；函数 `0.33`（偏移 `22485`，635～659）返回当前外观 ID 作为 avatar ID；函数 `0.30`（偏移 `20364`，566～578）以该 ID 查询头像表的 `UI.CoreParts`。这是 ID 参数与表键对应证据，不能证明网格已加载、当前热更新表优先级或最终渲染。

`work/bundle_package_inventory.py` 对本机全部 257 个安装 `Content/Paks` 从文件头逐条扫描至 footer 的 `index_offset`，共 1174183 个条目。加密目录索引没有解密；472992 个加密条目、116001 个超过 256 KiB 的明文条目明确跳过。355778 个有界明文解码中识别 10887 个有效 package header，以完整路径和精确对象名核对 497 个目标均未命中，855 个带 UE 签名的内容未解析。已识别的头几乎全部为地图，未识别 Texture2D／PaperSprite，不能把未命中解读为宣传图不存在，也不能猜测资源在哪个 PAK。全部 257 个包到达数据边界，异常为 0；私有扫描结果保留条目偏移和解码哈希，没有保存资源内容。

同一工具的 `--cdn-url-candidates` 检索另行完整解码 585190 个不超过 256 KiB 的明文条目，累计 18045678511 字节。41 处命中对应 35 个不同完整公开 URL，仅来自两个条目；其中 `ShareLogic.lua` 来自 PAK1 头偏移 `28583936`，SHA-256 `1afd5b0b7d3e109384d6468226bbd5da54b81bddda627279646e32af705aa7fc`。实际 URL 中的 `cdn.df.qq.com/G/CN/Resource/...` 只能证明这些具体地址，不能作为所有 Store 资源的根地址。没有取得 Store 完整 URL 或 CDN 配置根地址原值；查询串和 fragment 不保存，也未下载图片。新增包头解析器的 10887 条记录与旧扫描逐条一致。

对已经运行的同版本 shadow 客户端，只读捕获指定注册记录与有直接调用指令依据的有限代码段。原程序 SHA-256 为 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。快加载构造路径记录时，非 `/` 开头的字符串经过 `0x10cc77c0` 调用 `0x10cd5b10`；原 PE 偏移 `351100284` 的 UTF-16 单引号被用于拆分，成功后仅在右侧有末尾单引号时移除它。因此标准 `Texture2D'/Game/路径.对象'` 会生成不带类型和引号的回调键。`OnFastLoadComplete` 使用重新生成的键，仅将非空对象放入结果表。原 `ResImageUtil.lua` 的回调先检查原输入键并打印警告，随后仍通过 `next(map)` 取对象设置图片，没有因警告提前返回。完整代码快照 SHA-256 `c1afb08af3585d8c7c91f7015221f9009da0cd61b40c435172205e78e5330a86`；工具为 `work/probe_live_resource_implementations.py --object-path-calls`。这解释了警告可能伴随有效对象的代码路径，没有观察特定礼包的返回对象或像素，不据此替换源路径或宣称缺图已修复。

`work/read_live_cdn_settings.py` 先核验同版本 PE 的原生反射与 UHT 记录：`SettingCache` 的类型为 `TWeakObjectPtr<UAppSetting>`，原记录偏移 `351163144`；`Setting` 是偏移 `0x38` 的 `FAppSettingRow`，其 105 项属性明确包含 `MapleInfo` 和 `CDNRoot`，`MapleSettingRow` 的 10 项属性包含 `DefaultCDNUrl` 和 `CDNUrl_PC`。只沿这个已核实的弱引用读取一个对象数组项与三个 FString，校验索引、序号、标志、长度和字符串终止符，并在输出前重查引用与头。没有扫描其它堆对象、调用原生函数或写入游戏。

01:07 启动的原客户端在初始化前弱引用为 `index=-1`，工具明确跳过；随后同一 PID 的有效配置快照 SHA-256 为 `8cd7e771c3c093efefc57e4cd6fd91135028ae0c41c5fddf3caa8b008dfcea29`，共读取 686 字节／34 次。真实配置为 `DefaultCDNUrl=https://cdn.df.qq.com`、`CDNUrl_PC=https://repo.df.qq.com`、`CDNRoot=G/CN`。这些值证明配置来源，不等于已观察每张图片的最终请求、缓存命名或渲染；没有把默认域名代替 PC 域名，也没有给只有文件名的奖励图擅自补目录。该读取器的 24 项合成回归、CDN 定址采集的 11 项回归和图片路径采集的 13 项回归通过。

配置拼接采集 SHA-256 `eeb969f598c2ef8dc4dbf5cb83dde1422c09edac80f7da4a6299859e7d055ac0` 核验直接调用与模块内的十个分支字节。快照中 PC 选择位为 1，另外九个覆盖位为 0；结合已核实的 PC FString，源码求值选用 `repo.df.qq.com`。拼接 helper 去掉已知根前缀并插入 `/`，全部 202 个原始字段没有被移除的 `G/CN/` 子串。这里核实的是 getter 对输入的处理，没有调用原生 getter，也尚未核实图片 setter 在调用 getter 前的路径处理。

`work/check_bundle_cdn_resources.py` 对原始字段拼接地址作只读 HEAD 检查，[逐项状态清单](outputs/df-local-server/protocol/premium_shop_cdn_availability.json) 保留全部 219 行及 202 个原始引用，对 199 个不同路径的两种观测域名共发出 398 次请求，耗时 100.72 秒。两个域名各有 101 个 HTTP 200、98 个 HTTP 404，没有重定向、拒绝访问或超时；所有 404 对应原始无扩展名路径，所有 200 对应原表明确带 jpg/png 扩展名的路径。原始 FString 另行核对确认没有截断。HEAD 检查不读取正文、不保存响应头、不写游戏缓存；原始路径的 404 不是已经核实的原生最终请求 404，不能据此猜补后缀或下架礼包。清单记录来源、脚本及 HTTP 报告哈希，图片预处理、实际 getter 返回和最终渲染均明确未核实。

后续同一客户端的完整质量与路径组件快照 SHA-256 为 `6b24a730c4b74fb5f0833022cc3f1c67318dd4846c99db7528be8c12ca83a9f9`，同一 PID 的类型限定设置快照为 `a74b1307d96b683577bf3d62f555235d08ef6954984b0d272b1c9c381dd09e46`。原生 `SetCDNImage` 将 URL 与逻辑磁盘路径分别传给 `Req_Worker`；其当前扩展名开关和质量开关均为 0，枚举 3 在原生质量表中对应 7。完整路径组件证明：含字面扩展名的路径保持不变，无扩展名路径在原目录与完整原文件名之间插入 `/7/`，然后交给原请求队列。当前 PC 选择位为 1，覆盖位为 0，三个 CDN 配置值与先前快照相同。这是原生队列的 URL 构造证据，尚未观察每个实际网络请求及最终像素。

原生磁盘名称函数 `0xd61370` 使用初始值 0，将 ASCII 小写转换为大写，再逐个处理 UTF-16LE 的低／高字节；更新为 `(crc >> 8) ^ table[(crc ^ byte) & 255]`，没有最终异或。运行时模块的完整 256 项表与原 PE 偏移 `492415040` 的 1024 字节相同，SHA-256 为 `0053f121cdcaf9f510a940ba891fb2bccd41487953c5a4c0048c4a3ccdec782e`。原函数按 `=` 分出右段，使用不含终止符的原文件名（保留扩展名）计算 CRC，按有符号 32 位十进制与左段重新组合。缓存名称使用原始文件名，不加入下载 URL 的质量目录，也不采用 Unicode 全字符大写规则。

`work/check_bundle_cdn_cache_controls.py` 保留三个原始地址的 GET 控制范围。默认 CDN 上推荐 row 127／字段 272 返回 JPEG，共 `1732015` 字节，SHA-256 `f5cb8927c9313b696a3fb1db2e1fe16c6ca187bd1be0e97d493e9bbf7118cf50` 与既有 `C=951152861` 缓存前后完全相同；另外两个 PC 地址返回 302，未读取正文或跟随重定向，历史 Location 未观察。它们不证明其它资源的正文或原生最终请求。五项只读工具的 131 项合成回归通过；请求质量改写、CRC 表和 GET 行为分别记录，不用一次成功推断全部礼包已渲染。

补齐前另核对 row 105／字段 274 的原生 `/7/` 图片：官方默认 CDN 返回 `51807` 字节，与既有 `C=301908801` 的原始包装字节完全相同，SHA-256 为 `bdb3fbcb1b708ed3212ce2587a0edfe5d0810d714c7bf77b7f92170c480298eb`；原版 Oodle 有界解压为 `204800` 字节，解压哈希也与原缓存一致。[原生图片契约](outputs/df-local-server/protocol/premium_shop_native_resource_contract.json) SHA-256 为 `8febd6264ddfd10ce30cc2ba5f177c6f1f1be6daf77f662810a6392301454e2c`；[缓存控制记录](outputs/df-local-server/protocol/premium_shop_native_cache_control.json) 为 `153932f767a37e6cd24e8dc4ec812994c4e3d14ca5c34179f5b5b9c7c4395a15`。公开记录仅含源字段、原地址、长度和哈希，其他机器可随源码取得校验依据；不含图片载荷、进程地址或本机路径。

`work/repair_bundle_cdn_cache.py` 保留全部 219 行和 199 个不同 CDN 目标，仅对字段 272／274／276／277 已确认消费用途的 189 个目标建立修复计划。此次明确选择已观察的 `DefaultCDNUrl`，在报告中记为 `alternate_observed_base`；运行客户端的 PC getter 选择仍是 `repo.df.qq.com`，没有把默认域名冒称当前 PC 选择。脚本只在显式 shadow 中创建缺缓存，保留所有已有文件，校验原版 PE、资源清单、请求契约与解码器哈希；不跟随重定向、不发送账号信息、不改客户端 ID、源路径或资源头。

首轮 140 次请求均 HTTP 200，新增 138 个缓存，保留原有 49 个；两项未写入是 row 143／tab `10101054` 的字段 272、274。独立诊断确认两者是可完整解码的原版 PNG，但 IEND 后有附加字节，大图完整长度 `11077506`，超过旧 8 MiB 上限。大图 SHA-256 为 `5ad810632f411765f1f958cb0ed5c003aa6cac9612ebdad7d9e98fb594405c64`，PNG 流长度 `9086122`、附加 `1991384` 字节、尺寸 3456×1920；小图长度 `439995`、SHA-256 `c3cbdc91cf2797c04a471bb79273f12270b456d32ad969147700809ce6c1f3cb`、PNG 流长度 `328847`、附加 `111148` 字节、尺寸 640×320。工具只按这两条精确源路径、完整长度、哈希、流结束位置和尺寸支持原始文件；通用 PNG 仍需完整结构校验，原生包装解压仍限 8 MiB。重试两项均成功，原附加字节未裁剪或改写。

两轮合计新增 140 个官方图片缓存、`104514651` 字节：65 个原生包装、43 个 PNG、32 个 JPEG；全部新文件重读长度与 SHA-256 相同。当前 189 个已知目标（48 条推荐）均有缓存，93 个原生包装通过原版有界解压、50 个 PNG 和 46 个 JPEG 通过完整图片解码；初始快照中 47 个已有缓存哈希未变。再次生成计划没有已知目标缺缓存，未发网络请求。另 10 个只用于未知字段 304 的目标仍完整保留并排除自动写入。这次新增缓存从原表给出的官方资源地址取得，与迁移包早期只读提取的来源分开记录，游戏源安装未写入。[最终逐项报告](outputs/df-local-server/protocol/premium_shop_cache_repair.json) 是重试实际输出的原样副本，SHA-256 为 `a48b74074541c0b6d8e5cfb6d1bdbdd8358a9fc127a263819c8dcedf43f3eea4`，其中 187 个“保留”包含首轮已新增的 138 个，另两项为本轮“新建”；首轮原报告哈希 `cba786025535c60a85c44e413129a82ea07896067da07b2b8105c49be9ce3458` 保留用于历史核对，没有回写其失败结果或生成器哈希。

七项相关资源工具执行 177 项回归，173 项通过，4 项 Windows 符号链接权限测试跳过。02:03 原客户端试验完整结束，实际观察 `1800.72` 秒，记录完成和 SDK 恢复均为 true；源安装与 shadow 的 SDK 哈希均为 `9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723`。缓存解码验证不代替客户端纹理加载与全部礼包画面验证；本地虚拟资源的加密 PAK 归属仍未解析，枪皮只有文件名的字段仍没有猜补目录。具体位置和复用命令见[资源位置说明](docs/BUNDLE_RESOURCE_LOCATIONS_20261005.md)。

随后原客户端截图确认：推荐页许多底部小图仍空白，白鹰军团的 Logo 切换后大图仍保留上一项。原 `DataStructStoreRecommendItem.lua`（SHA-256 `3560dec1dce0c13e81bea6e4c036840f88bdc0341bfcf7c33312dad949793cc7`，条目 1856，头偏移 `8626176`）函数 `0.1` 从本地表读取大图、小图和 Logo；这些字段不能由未经确认的服务器协议字段替代。开放的 138 条推荐均有本地小图，其中 92 条没有 CDN 大图／小图。白鹰军团、先驱者、秘银工艺、趣味贴纸和腾驹驰春的原 CDN 字段均为空；仅补 CDN 缓存无法覆盖这些条目。

原 `RecommendHomepage.lua`（SHA-256 `6cdc643bba7457f7da74c3923635bca09805819fd1ea626c1e080f8243d84086`）函数 `0.30`、偏移 `24422` 对大图单独执行路径校验；本地校验失败且 CDN 为空时，没有清除上一张背景。Logo 为独立加载路径。另有非空视频配置时跳过静态大图的分支。当前证据确认这些失败分支存在，尚未证明特定截图实际走过哪条分支，不据此改写资源路径或伪造视频配置。

11:54 的独立只读试验确认实际推荐表 Outer 为 `/Game/R13N/Common/Base/DataTables/StoreHotRecommendation`。原程序完整 SHA-256 为 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`；来源注册链确认 `UDataTable.RowStruct` 为偏移 40 的 `UScriptStruct *`，当前 RowStruct 名称、Class 单例和对象登记均核验后才读取字段。158 个已分配行仅先读偏移 16 的 `uint64 TabId`，唯一匹配 `10101004/10101008/10101019/10102002` 后读取这四行偏移 160／176／192／224／248 的五个 FString；没有读取整行或调用原生函数。12 个图片字段与导出目录逐字一致，8 个视频字段为空。原生行名为 `4/8/19/40`，导出序号 `3/7/18/39` 只表示离线位置，不作为永久原生行名映射。私有采集 SHA-256 为 `fa383f30d94154ff6ce8fcb978c32d55f2a2f72dd8352461bc27563fc5f5a671`，源代码和所有已读元数据均在提交结果前重检。

随后用原生路径拆分、CRC 和 ASCII 比较规则核对这四项共 12 个原路径的缓存哈希链，未找到 `BluePrints` 子键，未取得终端文件名。私有报告 SHA-256 为 `50fcc87a15029a645155a8dd87c7db4396702f581060edf55a9e75c97afb355d`。查询仅复现有界哈希链，不认证独立稀疏位；缓存未命中后原客户端仍走文件名转换和虚拟文件系统查询，所以不将此结果当作最终 `CheckPathValid=false` 或纹理不存在的依据。相关行读取、缓存会话及适配器联合 83 项回归通过。11:17 试验完整运行 `1801.61` 秒、无遗留测试进程，SDK 恢复后与原安装哈希一致；本轮真实礼包购买序号 709、TabId `10102026` 返回 0，收藏通知和购买答复均已发送。

同轮修复 11 个刀具礼包的过滤和首次发货。刀具外观与 receiver 来自既有近战原表映射。`InventoryServer_Network.lua` SHA-256 `d7f83db2ae2cf4902b440131c15648c7b7d4b8b8f5e459231b9eb6ec17dcb0dc`，PAK1 头偏移 `34572288`，函数 `0.37`（偏移 `34027`，950～956）接收 `CSMeleeUnlockChangeNtf` 并调用 `0.15`（偏移 `16874`，408～430）更新独立近战实例列表。`ArmedForceDataLogic.lua` SHA-256 `4692ba32d36cfd05eb8e826aab7634dfad4955e1977c2cf0230ca6045109b020`，函数 `0.8`（偏移 `12697`，295～323）装备时查找真实 receiver 及 `weapon.skin_id`。因此新实例通知先于外观收藏通知与购买回调；普通库存通知不能代替这条专用消息。GID 是本地生成实例号，外观和 receiver ID 均保留客户端对应。

资源检查工具依赖 `outputs/df-local-server/requirements-optional.txt`。`work/bundle_asset_locations.py` 使用公开目录即可生成全部行；传入 `--game-root`、`--shadow-root` 核对实际缓存，`--evidence-root` 指向保留的原表和扫描证据，`--media-input` 合入只读媒体报告。缺少游戏目录或私有扫描证据时标记未知，不将空扫描结果当资源缺失。原 PAK 目录索引仍加密，本轮未确认所有本地图片的具体包归属及最终显示结果。

## 仓库拖拽改装与药品落位（2026-10-04）

14:02 的三次真实 `CSWAssemblyDepositPropUpdateReq`（序号 2186、2190、2195）都返回 `14026`，没有该路径的超时；旧服务将非空 `unequip_pos` 与换枪一起拒绝。原 `FastEquipLogic.lua`（SHA-256 `2201025fb81c87c4440f925acd3922b9fea20137173abc84e68cf7306eb25bf4`）函数 `0.0`、偏移 1319 的指令 75～83 取得拖入配件原位，103～128 创建卸装位置并跳过虚拟回收节点：没有实物旧配件时，只有 `loc`、没有 `prop_id/prop_gid` 是正常请求。真实替换事务核对原位和旧插槽，把实物放回腾空格；模型专用节点只保存在组件树，不落为仓库货物，也不碰与旧模型编号同号的药品。

节点表条目 4567 的 SHA-256 为 `0075368148ad3c2ffcaec020bfee36b1ac0bacd13506af1502c744ada5b137b5`。完整原预设树经双边父子连接核验，得到 592 条模型专用节点的机匣、父模板和插槽绑定，保存在 `protocol/weapon_model_socket_catalog.json`；缺 gid 的新模型只接受这些真实绑定。新树编号是本地保存标识，不是新物品模板或可交易归属。`18010000006` 的预设 `10010000123` 证明实物枪管 `13020000356` 的插槽 6 可连接实物 `13130000176`；模型 `13050000202` 的插槽 8 可连接实物 `13140000021`。因此移除模型父节点时仍须保留其实际拥有的子配件，不能整树丢弃。真实拖拽、同号药品保护、子配件卸回、重开及回滚已有加密协议回归；客户端显示效果另行记录。

13:49 的 `CSSerialCheapBuyReq` 序号 573 购买八件标准药品，原胸挂 `11070005004` 还有 11 个空格、背包还有 45 格，却返回 `14032`。原先逐件首个空位的策略先用小件占了唯一可容纳长件的分区。新规划优先保留原顺序落位，失败后只对本次新增物品作有限回溯，支持旋转，不移动已有物品、不改变目标容器；全批有解才扣费和保存。真实前态与八项请求逐字段匹配，新增五项及 117 项关联回归通过。每容器 100000 次候选检查是明确的本地计算限制，耗尽时整笔回滚，不冒称官方整理算法。

## 改枪台与购买目录对照（2026-10-04）

原 `GunsmithInspectorProcessor.lua` 函数 `0.55`（偏移 19447）要求 `IsBaseWeapon`、非零默认预设及模式匹配；`GunsmithInspectorProcessor4SOL.lua` 的 `0.5`（偏移 1761）读取 `GetPresetID4SOL`。按这条链核对 `RecFunction` 与组件节点条目 4567，恢复 98 套完整树，其中 67 套是这条购买路径的基础枪械。抽象预设价格和尺寸为 0／2 不能作为剔除枪种的依据；树必须由真实 receiver 根、唯一父子插槽和已知 GameItem 组成，缺失节点和冲突关系仍不生成默认树。

10-04 继续核查发现，旧筛选仅限制机匣子类 1～7，其它特殊机匣仍进入普通销售列表；去重后有 31 个，其中 27 个默认预设为 0、4 个没有 `RecFunction` 行。`WeaponFeature.lua`（SHA-256 `7da7cb28eb39f31aafc7cee14774108f524d56f789cc59a662741c4461c29f58`）的 `0.15`、偏移 6945 对所有 Receiver 返回武器类型。`AssemblySelectionDataLogic.lua`（SHA-256 `9a6661b89f501965de1e8cc94c74d9976eea965eb28fbe922e0bedf7f0e54ff8`）的 `0.10`、偏移 15616 先创建商品、后校验槽位；普通目录现仅接受已核实默认枪械机匣，另保留此前实机确认的商城条目 `18300000004`，不推断特殊武器的销售路径。已有物品仍使用独立回收目录。该消费者会显式将整枪预设转换为 RecId，没有据此修改交易 ID 或 `show_prop_id`。此修正不能单独证明一次 `desc nil,0` 告警的唯一来源，因为客户端静态槽位配置也会创建商品。

13:48 的原客户端提示已删除物品 `12080000002`，但该 ID 不存在于本地物品、协议目录、回收报价或当前 P90 默认组件树。原 `ShopServer` 的组件计价先查询客户端本地 GameItem，再查询动态价格；日志只能证明客户端本地价格链引用了缺失配置，不能据此给该 ID 添加模板、报价或替换映射。

`ItemBase.lua` 的 `0.54`（偏移 38902）从预设解析机匣名称和尺寸。报价按 `ShopServer.lua` 的 `0.131`（偏移 101597）及递归回调 `0.131.0`（偏移 104516）处理整枪；`0.115`（偏移 89229）确认模型专用部件不计价。本地单价仍使用已有初始指导价，不冒称官方实时交易价格。报价保留原预设 ID，实际入库为对应 receiver 和源组件树；名字或其它元数据相同不能合并不同枪种。源哈希、函数与销售边界见 `protocol/gunsmith_sale_consumer_evidence.json`。

两种原生购买失败的胸挂 `11070002005`、`11070008001` 没有可用的已核实布局：前者没有对应布局行，后者原行分区面积与声明容量冲突。GameItem 尺寸与价格不能替代具体分区。销售目录因此限定为现有 44 件已验证胸挂／背包，不编造格子；回收目录保留已拥有物品的计价。逐件真实协议测试验证报价、装备、分区响应与重读，旧失败报价不能扣款或替换装备。

容量消费者 `WeaponAssemblyTool.lua`（SHA-256 `3934cf763b87e4ea7cfc779b7db5541f913d321898143b1ff51293994a8d91c5`）的 `0.68` 对 nil／0 弹匣覆盖回退到基础值，`0.69` 按 `recId` 读取 `WeaponClipAmmoCount`；`0.71/0.71.1` 递归分离弹匣与其它部件的附加容量，`0.72` 对无原生容量效果返回 0。完整 19767 行 FunctionTable 已解析并核验尾标，现对 385 个源弹匣明确区分覆盖值和无覆盖；两种枪管的真实附加值 2 单独计算。销售枪中 65／67 个基础容量有来源，`18050000033/18010000049` 的 WeaponAttribute 未恢复，继续保持未知。

重建时旧缓存 `entry-4555.bin` 的哈希与目录记录不符，已从本机原始 PAK 重取 `entry-4555.uexp`，SHA-256 `5d4062a6d2c4ee563d34a25e4473054f2bb9b43b067c010bce9edf423f094e16` 与既有弹药来源一致，176 行及尾标完整解析通过；没有以这份失配缓存生成新物品关系。目录保留各源哈希及字段偏移，提取器遇到未核实容量函数时失败，不用默认猜值填满目录。

## 成交明细与超时请求（2026-10-04）

09:20 的原生试验中，六笔 `CSSerialCheapBuyReq` 均成功入账：`15050500001/04/09` 分别为 1／1／4 张，扣款合计 10,395,200。原 `AuctionServer.lua`（SHA-256 `ad10c29ff0fa53ca89ebebf9f0ba447cae2e47195b8921b24731cd01e4a82a6c`）函数 `0.77.0` 的指令 264～277 从 `res.orders[*].prop.num` 及 `buy_price` 累加实际数量、金额，278～280 判断是否部分成交。旧服务返回空 `orders`，因此客户端显示数量 0；新响应返回本次真实成交明细，单价与数量分开，失败事务不返回成交。此处 order_id 是本地卖单标识，不是客户端物品 ID；原函数 `0.13` 对部分售出卖单保留 ID 并扣减数量。

同轮未答复的四类请求由原 Lua 消费分支核对：`AccountServer.lua`（SHA-256 `6c27d297cd5d768dc537f79f0b1dea1e7ebd6a1bbd8860205f138143d1a2d5ec`）函数 `0.35/0.35.0` 允许无语音处罚消息；`FrontEndChatServer.lua`（`c376b2dbfd9b87e691dd04a49b706840129b6eef935d18914d24970b92adcda9`）函数 `0.34` 明确发送私聊已读 `(0,0)`；`GameModeServer.lua`（`c4ced93f1059d9cb8f91874a1d0084090d4263a95d443dcd7d9101548088e381`）函数 `0.289.0` 消费 `is_rank_enable=false`。本地无处罚、私聊历史为空、排位未启用，分别按这些实际状态答复；非零私聊已读目标或索引仍拒绝。

`PayServer.lua`（SHA-256 `a87fb1dd451a6c13b73fb84cbedfb27d91c03aeb6b4f699653e20f7cd029d7e2`）函数 `0.15` 发送支付上下文，回调 `0.15.0` 只打印结果；`0.22` 刷新商品后无条件更新上下文。旧服务返回 `ServerDisabled=10010`，原通用错误处理会弹提示，11:01 试验中共出现 9 次。当前已认证本地会话仅以 `result=0` 确认收件，不验证、存储、输出或外发令牌，也不改变余额和归属；这不是官方支付网关。各请求原编解码入口、消费函数和哈希保存在 `native_session_auxiliary.py`；鉴权失败保留拒绝响应。

10:12 的新版原生试验共 1023 条处理记录、0 条未响应。“东楼经理室” `15050100019` 实际购买 1 张，客户端提示数量 1、购买成功并存入仓库；随后该卡移入 `116001` 的分区 22，“典狱长收藏室” `15050500004` 移入分区 88，两笔响应成功并与存档重读一致。请求中的 `x/y=1/1` 是物品尺寸，省略的 `start_x/start_y` 使用零坐标，不能将尺寸误作落位坐标。此证据确认成交提示与实际存取，不证明监狱分区格子的界面已经显示。

11:01 的试验中 `CSRoomMatchStartAllocReq` 六次没有响应，客户端三次超时。原 `TeamServer.lua`（SHA-256 `446ddb180043f2c5d71cf91da5f9edaf9f2eb556fa54be0b82ce7546a2d0a268`）回调 `0.116.1`（偏移 94536）在失败时清理计时与发送标记，仅成功结果进入匹配。当前本地没有匹配服务，因此使用原 `CSRoomMatchStartAllocRes`、原序号及 `MatchGateServiceInMaintenance=139005` 答复，不生成节点、DS 地址或战局状态。错误名来自原错误表，编解码和来源记录见 `protocol/match_unavailable_consumer_evidence.json`；这是未启用服务的明确失败响应，不是战局功能。

## 辅助请求与研究奖励核验（2026-10-02）

`native_session_auxiliary.py` 记录了 7 类请求的原 PAK 编解码入口、SHA-256 与消费函数。`FriendServer.lua` 条目 6871 的 `0.41.0`、`QuickPatchServer.lua` 条目 6920 的 `0.4.0`、`InventoryServer_LabelLogic.lua` 条目 6885 的 `0.8/0.8.0`、`IDCSpeedLogic.lua` 条目 4938 的 `0.0.0/0.15` 均有明确空记录消费分支；按钮状态查询不产生点击记录，测速目录不生成服务器地址。`CSShopAutoRetroRewardReq` 和 `CSTlogAgentTglogReq` 没有对应 Res；`ProtoManager.lua` 的 `0.86` 对 Tlog 调用 `SendNtf`。本地商城扣款、奖励及记录同一事务提交，没有待补发队列；上报仅保留每账号最多 128 条摘要回执，不保存或外发原始事件。

`CollectionServer.lua` 条目 6860 的 `0.214` 触发低级租借券检查，`ArmedForceConfig.lua` 给出真实低券 `32330000001`，GameItem 堆叠上限为 10；这些消费者没有给出发放周期、数量或资格计算。旧服务返回 `CollectionPropDescNotFound=157012`，11:01 试验中触发 24 次错误提示。`0.214.0` 只保存下次时间，`AssemblyRentalMainPanel.lua` 的 `0.18` 仅在时间大于 0 时建立计时器；当前本地没有租借权益或发放计划，成功返回 `next_distribute_ts=0`，不发券、不写库存、不猜发放周期，未确认语义的 `prop_num` 不填写。13 个相关源及明确无计划状态的消费分支见 `protocol/collection_auto_distribution_consumer_evidence.json`。

20:19:39 的真实研究请求为奖池 `20300003`、轮次 7、购买 `32370000002` 共 25 枚，币种 `17888808889`、总价 2500、替代币种 `17888808888`。失败奖品 `28150150001` 位于 `LotteryProbDistribution` 条目 6774 的 source row 18；`WeaponSkinDataTable` 条目 7292 的 row 758、偏移 654877，字段 1820/1792/1794/1812 对应外观、receiver `18150000001`、预设 `10150000001`、开放标记。`CollectionServer.lua` 的 `0.14` 将主类 28、子类 15 归入枪械皮肤，旧提取器只保留 `280` 前缀导致漏行。修正仅补回原表 5 条 `2815` 外观，其中 4 条开放、1 条锁定。纯皮肤装备按已恢复外观表校验 receiver；10-04 的组件提取补回弓的源树，销售分类与挂饰路径仍未核实。挂饰资格单独限定为已恢复组件树的枪械子类 1～7，不由组件树存在推断特殊武器挂点；弓纯皮肤可装备，带未核实挂饰的批量请求整体回滚。`GunsmithPendantLogic.lua` 的 `0.5`（偏移 3466）无武器参数地取得挂饰列表，`0.16`（偏移 12305）只组装命令；机械组件节点不能代替挂点证据。16 项挂饰回归已通过。

日志分类核对了原函数：`LevelLoadManager.lua` 的 `0.35.0` 无条件打印完成计数，`LevelGlobalConst` 的 Success 为 0；`ServerManager.lua` 的 `0.6` 在处理器返回 true 后打印 process；`LuaResourcesRegister.lua` 的 `0.5.0` 打印 WaitLoadFinish 配置位。2026-10-04 进一步核对 `ResImageUtil.lua`（SHA-256 `af59a73e65c558c8865674d6e9e7c7a838c5d95d6772193f57c2eeea33b82ae6`）：回调 `0.0.0` 指令 11～18 仅在 `map[原请求路径]` 为假时打印 failed，没有返回；指令 19～29 随后取 `next(map)` 的对象并调用图片 setter。因此不能由此断言资源不存在或图片完全未渲染。另一条 `Resource load error` 才是路径已改变的过期回调，并立即返回。

原筛选日志的 75 次／16 条路径不是完整范围；同轮完整日志有 839 次／55 条路径，包含大厅和仓库基础图标，另有 24 次过期回调。`ResourceManager.lua`（SHA-256 `94c6b919058c79a213d514dcbded4dd9485fbb31d1c357ceaa4c89aee506a82e`）函数 `0.3` 默认走原生 `FastRequestAsyncLoad`，Lua 不转换这些路径为 CDN 地址；原生返回键及实际对象仍需运行时核对。257 个基础 PAK 和清单中 28 个 Dolphin PAK 均有成功挂载记录，29 项清单 MD5 与文件一致；资源版本字符串不同本身不是错误证明。相关包哈希一致、索引加密，尚无来源依据替换路径、制作占位图或按该日志下架商品。

## 可选初始化设置的空值响应（2026-10-02）

`SystemSettingServer.lua`（PAK1 条目 6945、偏移 35201024，SHA-256 `475e83736ef1a76a2df664a64ae85c145f6ba6bd96402ba839b9d991009d6d47`）的函数 `0.28/0.35/0.37/0.39/0.46/0.49` 读取 `PlayerSensitity`、`SaveBaseSetting`、`SaveSensititySetting`、`PlayerBase`、`InventoryAutoLine`、`SaveSOLMarkingItems`，回调在成功且 `kv.value == ''` 时保留客户端默认配置并跳过解码。

`IrisSafeHouseServer.lua`（条目 6894、偏移 34617344，SHA-256 `6f2fbc7857eab2ee033ebd67ea3e7036c556b5c349f7345b5e258a8807e0f367`）的 `0.1/0.1.0` 对 `SAFEHOUSE_LOC_KEY` 空值保留原位置；`FriendServer.lua`（条目 6871、偏移 34318336，SHA-256 `ec54b7529b3e50a6f5361682237113cc4e05f577d6272780ee6306f061e469fd`）的 `0.2/0.99/0.99.0` 对 `FriendDynamic` 空值保留原设置。服务仅对这些明确可缺省的键返回 `{result: 0, kv: {key: 请求键, value: ''}}`，不生成默认 JSON、位置或分享码，不新增存档记录。已有记录优先；未知键及授权错误保留原拒绝响应。

20:12 试验的五条失败请求只记录请求名和错误码，未捕获键字段。源调用链用于定位候选键，不能当成实际抓包字段；新日志仅输出这些已确认的键名，其它键记为 `<other>`，不保存设置内容。

20:39 新版试验的实际请求日志核验了 `SaveBaseSetting`、`SaveSOLMarkingItems`、`SaveSensititySetting`、`InventoryAutoLine`、`FriendDynamic`，修正后均成功返回；与源调用链定位结果一致。

近战目录的 18 组真实对应中，本地只提供原客户端收藏日志确认解锁的 15 组；`28101250021/22/23` 是尚未恢复拥有规则的系列中间档。旧记录 `18100000001` 已由用户截图确认显示为喷枪，迁移到实际基础刀具 `18100000002` 与外观 `28101200002`。收藏使用 `weapon_skin_props`，装备物品使用 `weapon.skin_id`，选择持久化到本地账号。`InventoryServer_Network.lua` 的 Move 分支会访问两端实际格子，刀具切换按其 Add/Del 分支下发，不把内部未装备位置 0 当成客户端格子。2026-09-30 原客户端实际装备 receiver `18100000014` 成功，用户确认名称、模型及切换正常。提取脚本与目录记录相关 Lua 哈希和静态函数依据；这属于本地测试账号的提供策略，不代表官方账号归属。

GitHub 协作仓库仅包含源码、静态 JSON 目录、重建描述符和来源元数据；不包含下文提到的原始表提取物、编译 DLL、测试账号或日志。迁移包与 GitHub 仓库的内容范围不同，克隆后无需先找回旧缓存即可使用已有目录继续开发。

以下路径均相对于 `game/` 游戏根目录；项目路径相对于 `deltaforce-local/`。运行时脚本通过 `work/local_game_paths.py` 定位 `../game`，也支持 `DF_LOCAL_SOURCE_GAME` 覆盖。版本目录 `1.101.37117.36` 和 PAK 文件名是**当前已验证游戏版本的资源标识**，并非这台电脑的安装路径；不同版本不能沿用这些表和偏移。

| 项目内数据 | 游戏内来源 | 处理逻辑 |
| --- | --- | --- |
| `outputs/df-local-server/protocol/game_item_catalog.json` | `DeltaForce/Saved/Dolphin/1.101.37117.36/Paks/1.101.37117.36.10_WindowsNoEditor_37127_P.pak`，资源表 `/Game/R13N/Common/Base/DataTables/GameItem` | 从已验证的明文 PAK 条目获得 `.uasset/.uexp`，`work/extract_game_item_catalog.py` 读取 Unreal 属性，按物品 ID 生成类型、稀有度、堆叠上限、长宽、重量和基础价格。目录头记录源表名、PAK 名与两个提取物的 SHA-256。 |
| `outputs/df-local-server/protocol/deposit_slot_catalog.json` | `DeltaForce/Saved/Dolphin/1.101.37117.36/Paks/1.101.37117.36.524_WindowsNoEditor_37641_P.pak`，资源表 `/Game/R13N/Common/Base/DataTables/PropSlotConfig` | `work/extract_prop_slot_config.py` 只读扫描并取出两个表文件，`work/extract_prop_slot_catalog.py` 按 PageId 提取格子长宽及容量。源提取物位于 `work/evidence/prop_slot_config/`。 |
| `outputs/df-local-server/protocol/operator_asset_catalog.json` | 同一个 `.524_...pak`，资源表 `/Game/R13N/Common/PC/DataTables/CharacterAvatarData` | `work/extract_operator_avatar_catalog.py` 从已提取的 `.uasset/.uexp` 解析外观行及 UI/TPP/FPP 网格路径。源提取物位于 `work/evidence/character_avatar_tables/`。这只说明模型资源存在，**不等于**该干员已解锁或时装归属已确认。 |
| `outputs/df-local-server/protocol/armor_durability_catalog.json` | 当前版本明文 PAK 条目中的 `/Game/DataTables/Armor/BodyArmorFunction`；原始 PAK 的具体文件名未保留 | `work/extract_armor_durability_catalog.py` 从 `work/evidence/armor_tables/` 的提取物读取护甲最大耐久。若需重新定位，先在相对游戏目录 `DeltaForce/Content/Paks/` 与 `DeltaForce/Saved/Dolphin/1.101.37117.36/Paks/` 的明文表条目中按完整资源表名检索，再核对提取物哈希；不能凭文件名猜测。背包、胸挂容量与耐久是不同属性。 |
| `outputs/df-local-server/protocol/business_contracts.json`、`generated_codec_fields.json`、`generated_class_metadata.json`、`candidate_business.pb` | 客户端 `DeltaForce/Saved/LuaSource/` 缓存与当前版本明文 PAK 内 Lua 容器；原生程序也提供部分类型名 | `work/lua53_reader.py` 只读解析 Lua 5.3 容器；恢复的字段、类声明和候选 Protobuf 定义保存在项目内。它们是重建业务消息的候选证据，不能单凭静态字段表宣称原客户端接口全部可用。 |
| `work/sdk-local-provider-stage/rail_api64.dll` | **本项目自建** DLL，接口形状来自同版本原版 `DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll` | `outputs/native-account-provider/provider.c` 与 `build_provider.py` 生成；`build-record.json` 记录原版 SDK、源码和成品的 SHA-256。包内无原版游戏 DLL。运行测试前会校验原版哈希并在结束后恢复。 |
| `container_layout_catalog.json` | 基础包 `pakchunk2-WindowsClient.pak` 中背包与胸挂表明文条目 | `work/extract_container_layout_catalog.py` 恢复每个配置的实际分区，目录记录条目与哈希；不能用容量反推格子排列。 |
| `safe_box_layout_catalog.json` | 当前安装基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 条目 7056，PAK 偏移 50318377，以及已有命名 `PropSlotConfig` 导出 | `work/extract_safe_box_layout_catalog.py` 校验源哈希、38 行与尾标记，直接读取 UInt64 模板 ID、原始两尺寸和容量，逐 ID 与 GameItem 核对；保存原始字段索引和行偏移，非方形横纵方向未恢复。 |
| `weapon_preset_catalog.json`、`weapon_component_catalog.json` | 同版本明文武器配置与基础包 `pakchunk2-WindowsClient.pak` 的组件节点条目 4567 | `work/extract_weapon_preset_catalog.py`、`extract_weapon_components_catalog.py` 恢复预设、receiver 和组件树，目录保留实际来源与偏移。 |
| `weapon_ammo_catalog.json` | 基础包 `pakchunk2-WindowsClient.pak` 条目 4489/4555；热更新 PartsData/PartsFunction；基础包 Lua `cs_deposit_pb.lua` | `work/extract_weapon_ammo_catalog.py` 恢复弹药类别、已有弹匣容量与装卸弹枚举，交叉核对客户端 Lua 规则；未恢复的弹匣或武器关系保持未知。目录记录源哈希、行偏移与函数。 |
| `client_error_catalog.json` | 基础包 `pakchunk1-WindowsClient.pak` 的 `errcode_pb.lua` 条目 6809 | `work/extract_client_error_catalog.py` 只读恢复实际错误名与值；不以统一猜测结果码代替库存业务错误。 |
| `melee_weapon_catalog.json` | 当前安装 `DeltaForce/Content/Paks/pak-0-0-pakchunk2-WindowsClient.pak` 明文导出条目 7276 | `work/extract_melee_catalog.py` 读取 18 行中序列化字段索引 40/41 的外观 ID 与武器 ID。源文件 SHA-256 为 `e6ab2c414dc8b972b0f20b647a8deedcb39c82912d968209f057db469defb845`。15 组对应由原客户端 `MeleeWeaponSkinDataTable` 日志交叉确认；加密名称表未恢复，不能冒称已解出原属性名。每行保留偏移、GameItem 名称键与尺寸。 |
| `gun_skin_catalog.json` | 当前安装基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 明文导出条目 7292 | `work/extract_cosmetic_catalogs.py` 从 1781 行恢复可与 GameItem 核对的 1781 条外观；序列化字段 1820/1792/1794/1812 分别关联外观、武器、预设和收藏开放标志。源 SHA-256 为 `03929c8c36ef4bd21de0e6262809095a863f3e65d6e44e8eefcf6ac57a59cce7`。本地提供 1518 条开放普通皮肤，曼德尔实例单独保存。 |
| `mandel_box_catalog.json` | 同一基础包条目 6764/6766/6768/7152/7134，以及已有 GameItem 导出 | `work/extract_cosmetic_catalogs.py` 保留 464 行箱体、558 行分组、3962 行奖励、11 项商城关联、5 项经验卡赠送配置及 34 种砖的 ConnectedPool。每行保留原始索引与偏移，各源 SHA-256 在目录头内；名称沿用客户端 GameItem 名称键。 |
| `premium_shop_catalog.json` | 当前安装基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 条目 7142/7156/7152/6774/6394/7154 | `work/extract_premium_shop_catalog.py` 恢复推荐配方、礼包价格、干员奖池、奖励与外观归属、主页签。所有记录保留行号、序列化偏移；完整来源和限制见下节。 |
| `profile_cosmetics_catalog.json` | 当前安装基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 条目 7110，`SocialAvatarDataTable` | `work/extract_profile_cosmetics_catalog.py` 恢复 2098 条社交外观 ID 与类别，字段索引 5213/5215；SHA-256 为 `50fe5c89e0ae53540ebf1a3df8cfca572b2c7558513516601f321fb12a7e8cbe`。原始行、偏移和解析数量完整校验；资源与开放时间仍由原客户端读取。 |
| `hero_customization_catalog.json` | 同一基础包条目 6614/6620/6624/6630/6632/6634/6636/6648/6660/6662；HeroData 条目 6628及礼包、研究配置 | `work/extract_hero_customization_catalog.py` 恢复 54 条服装、2049 条附件及默认标记。目录记录各表 SHA-256、行偏移、原始字段索引、独立奖励锚点和名称索引恢复方式；名称表仍加密，关联证据的不同强度见下节。 |
| `battle_pass_catalog.json` | 当前安装基础包条目 6358/6360/6362/6364/6368/6370/6372；原版 Shipping EXE 的结构注册、属性指针和成员偏移 | `work/verify_battle_pass_reflection_bindings.py` 先校验原 EXE SHA-256，再逐个 PE 节进行 raw/VA 映射；独立恢复 C++ 原属性名，并与原始 PAK 全部派生字段的序列、类型、长度和 FName 索引双向对应。502 行、131 个派生字段均通过后，`work/extract_battle_pass_catalog.py` 从原字段名生成价格、礼包和奖励；旧的顺序推断仅保留为已替代的来源记录。 |
| `weapon_pendant_catalog.json` | 同一基础包条目 6886 的挂饰表与已提取的 PartsData、GameItem 表 | `work/extract_weapon_pendant_catalog.py` 恢复 283 条真实 ID；本地普通挂饰提供策略要求两个可见布尔字段同时为真，80 条符合。原名称表仍加密，单个布尔字段名称未单独宣称恢复；神秘实例不凭空生成。 |

## 门卡基础表

`native_keycard_catalog.json` 的门卡来自当前基础包条目 6730 `KeyInfo`，334 条原行的地图与耐久字段通过原 EXE 的 `DFMKeyInfoRow` C++ 反射核验。`KeyFeature.lua` 使用表中 `Durability` 及物品 `health/health_max` 显示剩余次数；本地保存的零耐久不会被默认满耐久覆盖。条目 6726 `KeyBox` 的 109 行分区与条目 6728 `KeyBoxUnlock` 的 9 行解锁配置保留原字段和来源，物品位置 116、内容位置 116001 及分类限制由客户端配置确认。

`KeyBox.ItemID` 是序列化 FName，不能把包内索引当作数字物品 ID。现已从匹配哈希的原版 Shipping 进程只读解析配置：验证配置管理器、`GetDataTable` 接口、实际 RowMap 访问函数、分配位与 `KeyBoxRow` 字段偏移，再使用原生 FName 解码函数对应名称。`Key/KeyBox` 是原 Lua 消费的命名空间；它与 `KeyBox` 的 109 行逐项一致。`work/bind_native_keybox_catalog.py` 用 Index、MapID、初始槽数、四级槽数、BoxLength 八个标量的完整唯一指纹绑定 21 个 FName 组，保存源哈希与捕获哈希，不上传运行时指针或原始捕获。

104 行能对应现有 GameItem 的 20 个模板并用于布局；其余 5 行真实引用 `11120000011`，该模板不在当前 GameItem 目录，只作为证据保留。另有 6 个 GameItem 卡包模板没有匹配布局，继续拒绝，不按序号猜配。默认 `11120000001` 的 MapID 为 `[19,22,39,81,88,89]`，每区四格，总计 24；格子 ID 使用原 MapID，不能改成顺序编号。零到期权限与地图分区开放属于明确的本地测试策略，不代表官方账号归属。`KeyBoxUnlock` 名称绑定和扩槽写操作未恢复，当前只接受源表的初始可用格子。

2026-10-04 用户提供的门禁卡管理页完整列出六区，仓库中第六区被底部管理栏遮挡；用户取消安全箱固定后确认完整显示。`WarehouseEquipPanel_HD.lua`（SHA-256 `aee00b887b9d543173b02f513ff8bf3ff43ac05f2c12bd87aa4ee7a8472dd335`）的 `0.30/0.32` 读取 `SafeBoxbFixed`，`0.52` 将安全箱移入固定或滚动容器，`0.56/0.58` 控制管理栏显示而不调整滚动区底部间距。`WareHouseContainerBox_HD.lua`（SHA-256 `3bbb63844a5a8df643fe11c9e5698d3a0302a2feee7acdefb7d678c6337e3a61`）的 `0.31/0.32` 写入该布尔设置。只读核验 shadow 的 `Saved/Config/WindowsClient/LuaConfig.ini` 已保存当前账号的 `SafeBoxbFixed=False`；采用原客户端解除固定模式，未改分区数量、尺寸或地图名称。固定模式的原布局没有修改，配置重启后的读取与实际界面重开验证分别记录。

## 安全屋与任务来源

`native_safehouse_catalog.json` 从当前安装基础包条目 7068 `SafeHouseFormula`、7072 `SafeHouseUpgrade` 恢复 492/73 行；`native_quest_catalog.json` 从条目 6930 `Quest`、6934 `QuestLine`、6940 `QuestRewards` 恢复 2365/13/5585 行。两个提取器按原版 Shipping EXE 的 C++ 结构注册逐列核验名称、类型、字段偏移与序列化索引；目录保留每张表的哈希、原行及偏移。消费者 Lua 直接从基础 PAK 读取并核验条目和哈希，克隆后重新提取不依赖旧 `work/evidence` 缓存。

生产只使用源 `MaterialList`、确定 `ProductList` 与原始时长。该中文安装的日期按 UTC+8 解释，避免服务器主机时区改变开放窗口；保存设备生产线，事务扣除实际持有材料，到期一次性领取实际产物。此前 458 条受支持配方已在临时数据库验证生产、领取与库存通知编码。10-04 日志中配方 `100400900` 因预设 `10040000900` 的尺寸为零返回 `118008`；现按源映射关联实际 receiver `18040000001`，生产记录保留源预设，到期库存交付实际机匣与组件。开工前核验物理尺寸及完整树，领取失败保留生产线并回滚；蓝图、首领解锁、随机产物及未恢复物理来源仍拒绝。

任务状态和 Mission/Branch 类型来自实际 `common_pb.lua` 枚举；普通任务接受按源任务线、等级、前置领奖与冷却保存真实目标，`QuestServer` 成功回调依赖 `CSQuestDataChangeNtf`，因此通知在响应之前发送。2026-10-19 已接入简单目标提交及已验证奖励类型的原子领奖；战局目标仍要求实际战局证据，特殊类型和未恢复的复杂条件不会以空成功响应伪造完成。

## 配件装配与通行证核验

2026-10-01 的原生测试中，四次 `CSMallSellReq` 返回 14026；每批都包含已装 30 发弹药的 MP5。旧服务拒绝任何装弹枪械，导致全部货物回滚。原版 `ShopServer.lua` 的 `CalcSalePriceForWholeItem`（函数 `0.131.0`，偏移 104516）递归计算组件与枪内弹药；`CheckIfHasPrice`（`0.115`，偏移 89229）与 `GetShopDynamicGuidePrice`（`0.121`，偏移 95753）令 `IsModelOnly` 组件价格为零。已核对默认组件树中的 159 个不同模板均为模型组件。修正后的出售事务只使用数据库保存的实例树计算上限，并删除实际组件和弹药；客户端请求不能添加虚构弹药提高回收价。具体回收单价仍采用本地目录价格，不宣称还原官方动态市场报价。

`work/probe_gunsmith_native.py` 只读校验磁盘 PE，并用查询和读取权限查看 shadow 进程中已加载的原始函数；不写入游戏代码。插槽类型、深度、ID 和父节点函数分别来自 RVA `0x507efd0`、`0x507f160`、`0x507f1e0`、`0x507f060`，完整读取段哈希记录在 `dfserver/socket_guid.py`。实际购买 GUID `281474976710710` 对应根槽 54，`72339069014645763` 对应路径 `(3,28)`；不能将后者误当成 `(3,0)`。实现保留原生 32 位移位与 63 位父节点掩码语义，自动装配仅使用已核实的 0～3 层路径。原 Lua 单件购买分支只发购买请求，没有后续装配请求，因此服务端必须原子完成购买和装配。拍卖变更原因采用原枚举 `AuctionBuy=18`。

通行证当前目录选用安装内最新季 `202604`，不能据此声称其为线上当前活动。原 EXE SHA-256 为 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`；11 个节均同名 `.std`，须逐节按地址范围映射，不能按节名合并或把后部节误判为 overlay。礼包 11 的原字段为等级 20、价格 640，Lua `MakeGiftRewardList` 根据当前会员类型计算新增等级奖励，购买请求不含 `buy_type`，因此不会顺带开启会员。扣费、奖励和领取记录在同一事务，提交后才通知客户端；60 级奖励 `13460040086` 经挂饰目录核对后进入收藏。日期使用持久化的本地诊断窗口，经验卡与当前季线索的未恢复关联仍拒绝写入。

`work/evidence/` 在迁移包中仅保留上述小范围表提取物，以便不重新扫描整套游戏就能复核目录。大型原始 PAK、原始 Lua 缓存、历史抓包及日志不在包内。同版本游戏在新电脑上按相对目录可重新读取；重新提取前请先核对游戏版本与目录头内的源文件哈希。`work/evidence/character_avatar_tables/` 中 GameItem 的 `.uexp` 约 35 MiB，已压缩进迁移包，毋须额外复制游戏素材。

交易购买、货币扣减、装备落位和弹药展示不仅依赖资源表，还依赖客户端请求及服务端状态链。物品表中的价格、模型和长宽不是完整商城售卖规则；地图资源存在也不是解锁条件。缺失规则应从客户端同版本配置和交互协议继续恢复，不能把目录行当成可购买或可用的证明。

2026-10-01 用户截图明确要求保留“感知强化剂”所在行及此前常规药品，移除其后特殊药剂与饮品。`QuickOperationLogic.lua` 函数 `0.1`（偏移 4916，SHA-256 `6c6f9c474a1d54b12e280bfc14b5b34cd463401340da8ba74cb3fe199b2db8fe`）按服务端售卖名单及开放状态把 `ItemHealth` 行加入购买页。因此仅有 `GameItem.InitialGuidePrice` 不能作为上架依据。新的 `medicine_sale_policy.json` 是按用户要求制定的本地可售范围，不是提取出的官方上架标志；`ItemHealth` 完整行及特殊药剂、饮品逐项中文映射尚未恢复，不将未知名称猜配到 ID。

原客户端 `DFMGlobalConst.lua` 条目 1882 的主类指令 1124～1126 定义 `Medicine=14`，子类指令 1206～1222 定义治疗、手术、止血、持续治疗、维修和注射剂类别；SHA-256 `4887a7f2b5265a5277c5c2553f4ff56ec08f1219a632220e3b2efa367baddcc4`。本地开放现有物品表中子类 2～6 的 22 件治疗、维修用品，注射剂仅开放已核对中文名称的 `14070000001/03/04/05/06/08/09`，共 29 件。ID 主类、子类取法来自 `ItemHelperTool.lua` 函数 `0.38/0.39`，不是 `ItemHealth.MedicineType` 的页面四分类；函数、偏移和哈希均保存在策略文件中。

八种注射剂的中文名由基础包 `pak-0-0-pakchunk2-WindowsClient.pak` 条目 7068 双重核对：492 行导出中的原字段索引 497 是中文 FString，515 是物品 UInt64，516 的输出字符串含相同 `ID:1;`；每种还有一行重复产物记录。源 SHA-256 为 `b26f25dd754180c442e141e64fc19c2cdaa487347686c0bdb8779f7fffbcfa33`，所有行号与偏移保存到策略文件。`14070000006` 是保留的“体能激活针”，`14070000007` 是用户要求下架的“体能强化剂”；不得混淆。`work/verify_medicine_sale_policy.py --payload <条目7068导出文件>` 实际验证了 16 行中文、ID、产物字符串及源哈希。购买目录、报价和成交共用受限名单，回收计价仍按原物品目录及实际归属验证；不删除已有物品。

## 安全箱与仓库整理

条目 7056 的 SHA-256 为 `67e8779e53eba3eaaad941d177ad9baf4e49e06a83d3384438132d5ad9154480`，UInt64 字段索引 51 直接给出模板 ID，Int 字段 48/49 是两尺寸，62 为容量；38 行容量均等于两尺寸乘积。表名 `SafeBoxFunc` 由 1109 物品集合及客户端布局消费者支持，但加密名称表未恢复，不将数字字段冒称原属性名。`11090000002` 行偏移 269 为 2×2，`11090000004` 行偏移 665 为 3×3。本地测试账号提供这两个已验证真实模板的永久权限，`expire_timestamp=0`；这是本地账号策略，不是官方免费归属。其余非方形尺寸保留为原始 A/B，不猜测坐标方向。

命名 `PropSlotConfig` 导出 SHA-256 为 `1e1cfe1bd65be0b8a3bfb1eb5511e748e3adf8e17feffbb645b63bb6c499c830`：装备槽 109 行偏移 4052，内容槽 109001 行偏移 30431，后者 `bIsContainerByItem=true`、静态 0×0。内容限制采用此行的真实 `IgnorePropTypes` 前缀/具体 ID，并保留 GameItem 的安全箱标志检查；未恢复的 `UncarryableItem` 白名单、价值等规则不能宣称已完整实现。多个安全箱权限共用装备位 109 和内容位 109001，不是多个仓库页。

`ItemOperaTool.lua` SHA-256 `40de2bf2c60e09661ab4ac24e1bb0768719fbdc09bf71b12dc1645f0395a4892`，`DoPlacePermissionItem` 函数 `0.29`、偏移 26759，只发送 `prop_id/target_pos`。权限通过已认证账号查找，不能按缺失 gid 拒绝，也不能把权限箱当普通商品移出。`InventoryServer_Network.lua` SHA-256 `d7f83db2ae2cf4902b440131c15648c7b7d4b8b8f5e459231b9eb6ec17dcb0dc`，函数 `0.13`、偏移 15938 读取权限，`0.40`、偏移 35142 先处理位置变更，`0.50`、偏移 53269 优先按 `src_prop_id` 生成客户端布局。切换响应下发内容位 109001 的 Modify=3、真实模板及旧装备删除/新装备加入，随后刷新内容位置。`EquipmentFeature.lua` SHA-256 `f9be61db7cfc5a4bb3cc00e88bf3f51ea2c01dbfbbf6753d27d1e76dc0cb0600`，函数 `0.38/0.39/0.40`、偏移 16081/16335/16495，证明零到期值可永久使用，负值才标记免费，正值必须未过期。

原版整理设置请求是 `CSDepositSetCommonConfigReq`。`InventoryServer_SortLogic.lua` SHA-256 `b179130620dd63e41128c69218ad334535aa40e40990d6855933beeb6370bcd9`，`0.1`、偏移 1199 发送 `CSDepositSortMultiplePosReq`，回调 `0.1.0`、偏移 1619 消费 `changes` 后提示成功；`0.2`、偏移 3255 发送设置和 `extension_pos_order`。旧实现返回成功但空变更；现主仓库页 2 按命名模板的 9×40 格执行确定性落位并持久化，保存实例与旋转，失败整笔回滚。`sort_style=0/1` 与八个分类枚举来自 `common_pb.lua` 根函数，SHA-256 `81e071e35f33f0e5704d5098ac2a182c794bbe5b1e5a7e24f415a0473b40350b`；分类顺序已保存，但原 `DepositSortClass.ItemTypeID` 的字段关联尚未验证，当前分类模式仅按同模板分组，不声称复现官方分类及服务端整理算法。

`WarehouseWithTab_HD.lua` SHA-256 `6442714ffa908c79db4807438021da7be437559d71940b228e56517b0a212cac`：`_OnExtArrangeBtnClick` 函数 `0.61`、偏移 46636，单仓库且无钓鱼仓库时直接整理，多仓库进入选择；`_StartExtArrange` 函数 `0.62`、偏移 48113 绑定确认/取消/全选；`_OnConfirmExtArrangeBtnClicked` 函数 `0.67`、偏移 57653 将选择映射为真实仓库页 ID 再提交。仓库扩容 ID 算法来自 `InventoryServer_DepositLogic.lua`（SHA-256 `594f6ef7896cae11051fd67d365160af4afb699b51c0febb794e7c9dc588bb84`）函数 `0.17/0.18/0.20/0.21`、偏移 10182/10329/10632/11243；模板槽 1001 不能当成已拥有扩容页。扩容配置和分类表候选尚缺命名字段的独立对应，不生成假扩容页，不宣称多仓库分类整理已恢复。

2026-10-01 11:29 的原客户端试验捕获了 34 次 `CSDepositEquipPropReq`。请求序号 1821 的 `spec_loc` 指定胸挂分区 5、`start_x=1`，省略默认的 `start_y=0`；1843 反向省略 `start_x=0`。序号 1903 同时指定 `target_prop_gid`，属于交换，不能只移动源物品。旧实现遇到省略的坐标改为自动落位，并忽略容器内交换目标，随后四次 `CSDepositAssemblySyncBodyContainerReq` 在胸挂分区 5 出现两件物品同占 `(0,0)`，数据库副本重放确认拒绝原因为 `POSITION_OCCUPIED`。现在保留明确位置的零坐标及旋转，交换两件实际拥有的实例，无法容纳时整笔回滚；不接受重叠快照，不删除物品来绕过错误。

上述字段来源为 `EquipPropCommand` 的 `target_prop_gid` 字段 6、`spec_loc` 字段 10，以及 `PropLocation` 的 `start_x/start_y` 字段 2/3、`rotate` 字段 7。来源 Lua 的 SHA-256 分别为 `9e0e59f87781ec6184a52b3cf09e661084945b1330ecc0bc8c4e671c1a364d01`（`cs_deposit_editor_pb.lua`）与 `5fe89634d480907ba0f4657ef699151e147594750ddba37247a50d718ac8b753`（`ds_common_editor_pb.lua`）。`InventoryServer_Network.lua` 函数 `0.43/0.44`（序列化偏移 44387/45587）分别按响应移除源位置、设置目标位置；SHA-256 为 `d7f83db2ae2cf4902b440131c15648c7b7d4b8b8f5e459231b9eb6ec17dcb0dc`。位置冲突改用已提取错误目录中的 `DepositSpaceHasOccupied`，不再笼统归为 `DepositInternalError`。

`ItemLocationDefine.lua` 函数 `0.5` 的指令 10～11 将协议 `loc.rotate` 直接赋给 `bRotated`；`ItemBase.lua` 函数 `0.76` 的 `IsRotated` 读取此位置状态。仓库中非方形物品旋转后，除存档尺寸外，移动与库存重取响应也必须返回保存的旋转标记。独立审查在临时数据库复现旧响应固定为 `False` 的问题；修正后加密接口用例验证 3×1 医疗物品旋转、重新拉取和后续移入胸挂的方向一致。

口袋位置由已提取 `common_pb.lua` 根函数指令 426-428 确认：`Pocket=199997`；指令 399-401 的 `CarryOutPropsPos=1999` 是另一个位置。该 Lua 提取物 SHA-256 为 `81e071e35f33f0e5704d5098ac2a182c794bbe5b1e5a7e24f415a0473b40350b`。`QuickOperationLogic.lua` 根函数指令 51-61 将 Pocket 纳入身体容器快照，实际请求中有五个 1x1 口袋分区；购买与重开页面均按这个真实位置持久化。

心跳 `tick_count` 是客户端时钟的 Unix 秒，不是进程运行毫秒。2026-09-30 从当前安装 `DeltaForce/Content/Paks/pak-0-0-pakchunk1-WindowsClient.pak` 只读提取：

| 条目 | 客户端函数与依据 | 提取物 SHA-256 |
| --- | --- | --- |
| 7032，`ClockManager.lua` | `0.9` 直接记录服务时间；`0.11` 加上本地秒差，供商品时间判断使用 | `780f5d721f03c8965496a36fec011647d4bd9d45184dd9a2cc839a8f11b83a1e` |
| 7333，`TimeUtil.lua` | `0.1` 的 `GetCurrentTime` 调用 `os.time()` | `953acb6204def71e92ca497c9d74df65f60abd95fcaa17f34b3be18ae5a83260` |
| 7131，`ProtoManager.lua` | `0.82` 的 `UECall_UpdateServerTime` 将响应 `tick_count` 直接传给 `ClockManager.UpdateServerTime` | `83773304fcbaaceb2b335d4ba92fd14b95de31c490ae08e66df55ec67ef91c82` |

已提取 `AuctionServer.lua` 函数 `0.45` 将 `auction_vaild_time_begin/end` 与 `ClockManager.GetLocalTimestamp()` 比较（SHA-256：`ad10c29ff0fa53ca89ebebf9f0ba447cae2e47195b8921b24731cd01e4a82a6c`）。错误的心跳时间会在商品详情拉取后将其判成未开放；首次目录尚无此时间窗口，因而首次有选项、再次进入丢失。使用 `work/scan_weapon_tables.py --baseline --pak-name pak-0-0-pakchunk1-WindowsClient.pak --lua-pattern 'ClockManager|TimeUtil|ProtoManager' --asset-pattern 'a^'` 可重新取得时钟来源，用 `work/summarize_weapon_lua.py` 静态查看函数，不执行客户端 Lua。

单条防具报价的档位同样来自客户端逻辑：`AuctionServer.lua` 函数 `0.17`（指令 40-57）仅在头盔或护甲恰有三个报价档位时读取 1/2/3，否则读取档位 0。`GoodsItemStruct.lua` 函数 `0.13`（指令 8-15）把 `GetSaleInfo()` 是否有报价作为交易购买解锁条件；当前安装基础包 `pak-0-0-pakchunk1-WindowsClient.pak` 条目 1778 的该提取物 SHA-256 为 `34ae5cbc845b364949e34633630642150aced86398d1b6263b8b453a616f7ffa`。本地仅提供一个满耐久报价，类型目录及商品详情必须一致使用档位 0；此档位是报价索引，不能当成物品实际耐久。2026-09-30 原客户端请求并成功购买护甲 `11050006001` 到位置 105、头盔 `11010005011` 到位置 101，SQLite 重读确认两者持久化，用户确认四类装备均可购买。

## 枪械皮肤与曼德尔协议

2026-10-01 客户端日志出现 `ShopLotteryDataTable` 找不到 `MandelItemId=16110000001`、随后 `MandelDrawOnly` 读取空奖池。该物品存在于基础物品目录，但没有原版 `StoreLottery` 的商城关联，不能因 ID 前缀相同而上架。现在购买列表只接受 `16110000014`、`16110000017` 至 `16110000026`，共 11 个实际商城关联；每项同时核验 `MandelItemId`、箱体及奖励分组。已有旧物品保留原 ID，不假造旧 ID 到新奖池的映射。

普通外观归属是本地测试账号的提供策略。外观 ID、武器 ID 和预设关联来自客户端目录；`ItemHelperTool.lua` 函数 `0.40/0.60` 的 ID 分类规则用于区分普通与曼德尔外观。没有把未恢复的挂饰、花纹、磨损或材质 ID 写入账号。曼德尔奖励实例使用客户端 `CollectionServer.lua` 函数 `0.11.3/0.206` 明确支持的 `appearance.id=0` 默认查表分支；该值是客户端哨兵，不是假造 AppearanceID。

`MandelDrawOnly.lua` 函数 `0.5` 通过 `GetCollectionPropById(GetKeyID())` 读取密钥，因此 `32320000001` 必须作为收藏道具下发。该提取物 SHA-256 为 `f02cd1f699e83b7884bdf0a40f5b494600ceff39d26e055354dd641a86b01118`。`CollectionServer.lua` SHA-256 为 `30fd97e50c22998e987b1fdcf8ee7a0e4edfe1ae51b93dc1d6e11ff5e7bf37f2`。商城条目 7134 的字段 19/11/21/9/20 对应赠品、货币、价格、商品、赠送数量；实际购买商品是 `32210000004` 武器次级经验卡，每个 60 三角币，附送一个量子密钥。密钥请求的 `price` 是该次经验卡购买总价，砖请求的 `price` 是单价，二者由原客户端实际请求交叉确认。旧密钥货币记录在同一个 SQLite 事务中迁移为收藏数量并删除旧记录，重复启动不会再次赠送。

`StoreServer.lua` 函数 `0.119.0` 成功回调直接执行后续扫描；`MandelDrawOnly.lua` 函数 `0.36` 会再次检查收藏数量。因此本地购买先发送 `CSCollectionPropChangeNtf`，随后发送购买响应，保留请求业务序号并递增外层包序号。

`CollectionServer.lua` 的 Add 分支按物品 ID/gid 替换当前栈，不把 `prop.num` 当增量累加。重复购买必须下发交易后的总量，`delta` 单独表示本次购买数；重连加密接口用例验证两次各买 10 个密钥后，通知与数据库均为 20。

十连奖励展示的约束来自 `RewardServer.lua` 函数 `0.17.0`：所有 `Add/Modify` 且 `prop.num>0` 的行都会进入奖励列表，不检查扣除的负 `delta`。该提取物 SHA-256 为 `12c62cdedc2d117e444b63c37e7e538f907d52b9976d7acb66c658c2c59d1dec`。2026-09-30 22:23 崩溃堆栈经过 `RewardSceneViewTen.lua:513/674`，向十件展示场景传入了十件奖励及两个剩余消耗栈。现在剩余砖和密钥仅通过收藏通知同步，扫描响应只提供实际奖励；回归用例通过真实加密包和重连处理入口检查该约束。

上述十连展示 Lua 来自基础包 `pak-0-0-pakchunk1-WindowsClient.pak` 条目 5556，SHA-256 为 `bf1e6845d4e398234ce5469c19734dc5fcb167800c8e00453316b72acc7cb258`。函数 `0.19` 对奖励列表逐项调用 `SetCurveLinearColorByItemQuality`，与崩溃堆栈一致；函数 `0.22` 进入抽奖子场景后执行该调用。

扫描规则分为客户端配置与本地执行策略：分组启用、权重、核心标志及 `TimeAssured=75` 来自分组条目字段 562/577/567/582；奖励 ID、数量和启用标志来自奖励条目字段 3982/3977/3967。本地使用配置分组权重，在组内均匀抽样，并按配置次数与本地连续未出核心的计数执行保证规则。组内动态概率、官方计数语义及增量调整规则未恢复，因此这套执行策略和显示的 `real_prob` 仅表示本地服务行为，不能宣称为官方概率。原始 `ProbShowed` 保留并单独下发。砖的 20000 曼德尔币报价也是本地诊断策略。奖池、名称、ID 和模型关联均采用已恢复的客户端配置。

## 原版商城与干员研究

2026-10-01 从本机安装只读提取，原始缓存是否存在不作为前置条件。当前基础包内已包含安魂、狂怒、飞虎、猛火强攻、游园惊梦及群星补给所引用的配置和资源路径。名称和宣传图仍由原客户端自己的配置读取，本地响应不编写替代名称或素材路径。与官方在线服务一致的活动轮换清单未恢复，不能把本地展示目录宣称为官方当前售卖清单。

| 基础包条目 | 提取内容 | SHA-256 |
| --- | --- | --- |
| 7142，`StoreHotRecommendation` | 158 条推荐配置及真实礼包配方、分项原价和包内价格 | `bcf064ebee25d046e21712375adf8e68f80b71bedd9c5c65f1fcb6a6d771a1fc` |
| 7156，`StoreMallGiftConfig` | 61 条特供配置、礼包内容、价格、日期、限购及原始支付商品标识 | `1b7640b1121e61e9fef64a8f986f5620588fb1e9a70822f8feae9898056b68d7` |
| 7152，`StoreLottery` | 19 条商城抽奖关联，其中 8 条为干员研究，11 条为曼德尔 | `9afbcc8eb3b98d08ee45b4ef0cea12464decb9f82b1faeb64337a2a25d757e62` |
| 6774，`LotteryProbDistribution` | 64 条干员奖池奖励，保留原始成本字段 69 与权重字段 72 | `c18ea9aaff395fc15dead24004e52d7fc9339c617667cd240e4f2b079d7b2563` |
| 6394，外观关联导出 | 54 条外观 ID 与干员 ID 对应，字段索引 112/113；加密名称表未恢复 | `efacdce4b68c07df77ed86589b4a79159e22a643bfdb188c8e0dae3d98eb2d74` |
| 7154，`StoreMainTab` | 原生四页签 `HotRecommendation/StaffLottery/MandelLottery/WeaponSkinSales`，以及两个有条件的活动页签 | `bc952ca89fb4548e9ae7976e0c14c486303ac5978e91a6278a842fa8e5fab467` |

安魂对应 `20300008`，原表全局行 ID（字段 73）为 `57` 的奖励包含外观物品 `30000060010`；条目 6394 将该外观关联至 `88000000029`。协议 `num_id` 使用字段 81 的池内 `SortIndex=1`，不是全局行 ID。`StoreServer.lua` 函数 `0.83` 按 `LotteryId/SortIndex` 查表，`StaffLotteryMainUI.lua` 函数 `0.13` 按奖励表长度判断已领完；返回稀疏的全局 ID 会使 Lua 长度为 0，误显示已获得全部奖励。八个池均返回原表池内序号 1～8；旧存档全局 ID 在读取时映射，不再次发奖或扣费。不能把安魂外观换成另一个奖池的 `30000060008`。飞虎礼包 `10104007` 中外观 `30000050013` 对应 `88000000025`，四个语音物品分别为 `38050050066/67/68/69`，不能把连字符配方当成一个新物品 ID。

推荐图的本地路径不可用时，原客户端会使用 `HotRecommendationPropDesc` 的四个 CDN 字段（协议编号 20～23）：`IamgeSourceSmall_CDN`、`IamgeSourceBig_CDN`、`ImageSourceLogo_CDN_CN`、`ImageSourceLogo_CDN_EN`。对应源表序列化索引为 274/272/276/277，保留原始 `Resource/Store/` 地址和扩展名，不编造图片路径。`StoreRecommendBanner.lua` 函数 `0.10` 与 `RecommendHomepage.lua` 函数 `0.30` 调用 `LuaSubsystem:CheckPathValid` 检查本地图后再选择 CDN。条目 `10102077` 没有任何本地或 CDN 地址，故不作为可见推荐，但保留原始目录和历史购买记录。其余条目有资源引用并不证明本机素材已成功加载，仍须原客户端验证。

曼德尔页签的奖池也必须带开放时间：`StoreLotteryItem.lua` 函数 `0.2` 保存 `begin_time/end_time`，`StoreServer.lua` 函数 `0.101` 筛掉未开放的池，主页面在列表为空时隐藏页签。11 个曼德尔池使用与干员研究相同的本地诊断开放窗口；这是本地开放策略，不代表官方活动轮换。

协议消费者来自基础包 Lua。`StoreServer.lua`（SHA-256 `71987b0e506b13d19e57e813f64e09552482df76a17fe94302d91149f7d44d0e`）函数 `0.4/0.126` 等待配置、购买记录、主题时间和活动配置，并按真实 tab/goods ID 查客户端表；`0.145` 允许整包购买省略 `item_ids`。2026-10-01 02:19 的原客户端请求确认：全部付费皮肤已拥有时，整包请求可省略价格，以零价领取未拥有赠品；单买外观 `30000050029` 报价为原价 2210。服务按归属和原始配方核价，不接受客户端任意零价。

`StaffLotteryMainUI.lua`（SHA-256 `38f9665d38e53c4ac1af22494e9020045911edc834b45eee2aa9334f2c02f4a2`）函数 `0.10/0.27` 从已获奖励数量计算下一轮，并将不足的研究密钥购买放在 `buy_prop` 中。02:18 实机初始查询省略 `lottery_id`，需要返回全部研究奖池。`HeroServer.lua`（SHA-256 `6e56ce2b082124aceae30488055b866a29954869e8c4c8626efb24a49fc660be`）函数 `0.116` 通过 `CSHeroUnlockNtf` 更新外观归属；购买响应之前必须同步完整干员外观列表，装备另外保存并检查物品所属干员。

本地研究抽样使用字段 72 的权重，从剩余奖励中抽取；成本依次读取字段 69。获得核心外观时发放本池全部剩余配置奖励，历史与消耗在同一事务中保存。此抽样与离线开放时间属于明确的本地诊断规则，未恢复官方动态概率或活动排期。加密字段名仍未知，不宣称已完整还原原始概率表。

特供按已恢复的配置日期和限购执行。购买记录按 goods ID 合并，周限购只返回当周数量。尚未恢复武器外观装备映射、空间物品发货或支付方式的条目保留在提取目录供研究，不向客户端提供可购买报价。原版现金礼包在本地测试中校验原始商品标识后直接发放配置内容，响应禁止继续调用外部支付 SDK；不提交真实订单，不代表官方支付流程已恢复。

推荐页的 16 条奖池宣传项配方为空，但不是空商品。条目 7142 的字段 282 保存实际跳转目标字符串，例如安魂 `10210005 -> 20300008`。基础包 `pak-0-0-pakchunk1-WindowsClient.pak` 条目 1856 的数据类 `StoreRecommendItem.lua`（SHA-256 `3560dec1dce0c13e81bea6e4c036840f88bdc0341bfcf7c33312dad949793cc7`）函数 `0.2` 从服务响应读取 `jump_to`；`RecommendHomepage.lua` 函数 `0.27` 的 `banner_type=2` 分支转交该目标到商城页签事件。服务提供已恢复奖池的原始宣传项和目标，购买接口仍只接受实际商品配方。未恢复活动跳转的 `banner_type=3` 条目保持关闭。

账户社交外观使用 `CSCollectionUnlockAvatarsReq` 查询实际收藏归属，`CSAccountUpdateAvatarReq`、`CSPlayerUpdateMilitaryTagReq`、`CSPlayerUpdateTitleReq`、`CSPlayerUpdateHonorMarkReq` 更新装备。登录与重连通过 `pic_url/military_tag/title/honor_mark` 恢复，头像按原 `AccountServer` 用法返回 ID 的字符串。`RoleInfoServer.lua` 函数 `0.19` 在收藏通知含社交物品时重新查询归属，`0.20.0` 遍历原表构建已获得和锁定列表；不用把全目录赠送给账号。`SocialChangeTitle.lua` 函数 `0.19` 明确以 ID 0 卸下称号或徽记，SHA-256 为 `a49b991f716d0fc5c61d2b3860901aee4490b985fbf19bfa6c3f385fe4eee760`。未知 ID、错误类别或其它账号拥有的物品不能装备。

## 干员自定义

`HeroServer.lua` 函数 `0.18.0` 从 `CSHero.fashion_list/accessories` 建立列表；客户端不会补齐服务省略的服装或附件。`HeroWatchMainPanel.lua` 函数 `0.2` 将本地手表配置与服务器附件列表求交集，原先没有 `accessories` 就会显示空页。现在提供适用于每个干员的完整锁定和已拥有列表，仅实际收藏或原生默认标记解锁；获取服装、手表、名片、语音等后先通知对应干员，再执行购买回调。

详情筛选不等于名单筛选。`HeroServer.lua`（SHA-256 `6e56ce2b082124aceae30488055b866a29954869e8c4c8626efb24a49fc660be`）函数 `0.19` 分批发送 `hero_id_list/filter_by_id`；回调 `0.19.0`（偏移 27911）仍以响应 `hero_ids` 替换完整名单，再由 `0.17`（偏移 21702）删除名单外的干员、服装与附件缓存。`0.100`（偏移 85369）在服装缓存被删除时返回套装 ID 0。服务现仅筛选 `heros` 详情，所有加载响应保留完整 17 个 `hero_ids` 和账号选择字段；加密响应回归覆盖全量加载后的单人及空详情刷新，按原消费者规则验证名单、所选干员与服装缓存仍保留。

2026-10-01 11:12:55 原客户端 `CSHeroEquipFashionReq` 序号 823 为干员 `88000000029` 装备 `30000060010`，`new_fashions` 只带 `id`，省略默认值为 0 的 `slot`；旧校验将省略字段视为 -1，返回原错误码 `117302`。`HeroFashion` 来自 `ds_common_editor_pb.lua`（SHA-256 `5fe89634d480907ba0f4657ef699151e147594750ddba37247a50d718ac8b753`），字段 1 是 `slot:uint32`。现按已核实的 `FashionSuit=0` 处理省略值；真实请求编码回归验证抽奖外观可装备并重读保存，非零槽位及未拥有服装仍被拒绝。

原版使用按钮的“正在使用”表示已装备：`HeroConfig.lua`（SHA-256 `3fb52f24168638c364fffb8d2840e60ef441c814b2310841324f73d53c5a3be1`）常量 196～198 将 `Using/Lua_Hero_Text_Using` 对应到此文字。`HeroAppearancePanel.lua`（SHA-256 `51f629c7c3ba80c5ac1aee6814c4b7231d7b5f69f21e131514f14fa63e47f450`）函数 `0.27`、偏移 26458 依据 `item:SetOperated()` 选择“正在使用”并禁用按钮，未装备时显示“使用”；成功回调 `0.27.0.0`、偏移 27867 刷新按钮和当前外观。2026-10-01 11:30～11:31 原客户端三次分别装备 `30000020004/30000040007/30000060010` 并同步处决，响应均成功；用户截图基础套装已装备的绿色圆点与禁用按钮一致。原版已装备状态与当前服务响应一致。

套装位置 `FashionSuit=0` 来自基础包 pakchunk1 条目 6801 的 `ds_common_pb.lua`，SHA-256 为 `6f1bec3a236dbd47c28d932a2702bc8cc386ecb6119312d71d57a62d6e8b8f6b`。`DFMGlobalConst.lua` 条目 1882 提供实际附件类型，SHA-256 为 `4887a7f2b5265a5277c5c2553f4ff56ec08f1219a632220e3b2efa367baddcc4`。`HeroHelperTool.lua` 函数 `0.89/0.90` 判断默认附件与通用归属；`HeroServer.lua` 函数 `0.68` 的喷漆、展示动作、手势和语音共享槽位规则用于保存装备。处决与服装的限制来自原表字段 50及八个研究池中的皮肤/处决对应，由 `HeroHelperTool.lua` 函数 `0.139` 交叉核对。

加密 Hero 名称表没有解密。目录逐关联标记 `independent_bundle_anchor` 或 `numeric_fname_order_reconstruction`：前者有原礼包或研究奖励及干员对应的独立见证；后者由本安装 44 份明文名称表一致的数字名称字典序、HeroData 的 23 个实际干员 ID 锚点及连续索引范围恢复。两类证据不能混称完整原始名称表。每个见证均记录条目、行、偏移与实际 ID；主物品 ID 必须与已有 GameItem 名称键相符且在所有有效匹配中唯一。

默认服装用 17 套已核对 UI 模型家族的对应，避免同名换色行被错当默认解锁。未恢复命名来源的击杀语音类型 10、战局技能装备类型 11及 `CSHero.sol_expert_data` 技能关联没有编造。完整干员目录约 358 KiB，原服务 64 KiB 默认策略会阻止出站编码；仅目录与解锁通知提高到 1 MiB，接收限制保持原值。端到端用例验证真实加密响应、研究奖励到外观与手表装备，以及数据库重开后的恢复。

`CSHeroGrowLineRewardViewReq` 被原通用查询处理器的动词过滤拒绝，导致每次加载干员后发出的预览查询没有响应。`HeroServer.lua` 函数 `0.22/0.22.0` 将响应的 `hero_id/rewards` 保存为成长界面的预览缓存，不更新收藏或装备。当前本地未配置成长奖励，因此仅为 17 个已支持干员返回明确的空预览，未知干员使用原错误码；查询不改进度、不发奖。基础包条目 6644 的 153 行 HeroLevel 数据中，两组数组全部为空，字段 171 的目标 ID 不是 GameItem 奖励 ID。非空成长奖励来源仍未恢复，不能宣称成长奖励系统已实现。

## 大厅赛季元数据（2026-10-06）

`CSSeasonGetInfoReq` 原先走通用空查询，只返回成功码，缺少 `cur_serial` 和日期。大厅实际依赖排位接口，而非通行证接口：原版 pakchunk1 的 `HallSeason.lua`，偏移 21645312、SHA-256 `f01e9f6781a24505de1806b564bfac5602e25c233f73b0a515451117a0f1c16c`，函数 `0.9` 用 `GetCurSerial` 查 `SeasonName`；`RankingLogic.lua` 函数 `0.27` 用 `RankingSeasonInfo.Index` 匹配序号，SHA-256 `7e2083615f7141bbd1e5b41c892e406819c968b2605d1644bf87f530d0eed9e8`。`RankingServer.lua` 函数 `0.7.0` 保存响应的序号、UI 日期及排位摘要，SHA-256 `e9fd084a84edf188cfe094a3ccc167349654b76d044c0a2ff6d97f2e17e9597a`。

`native_season_catalog.json` 从原版 pakchunk2 完整类型化提取：`RankingSeasonInfo` 条目 7004、偏移 50250809、SHA-256 `c17cb4f3a61ae6c2b2ca68a031fbf6386b3cea1ee583f96c85465d3a61ef63a2`；`SeasonDataRow` 条目 7080、偏移 50365305、SHA-256 `e2f33dd5e6cef30f5555ffc269ac29a9e2cfd608f1a5229e763a04d5622ef5cd`；`TournamentSeason` 条目 7204、偏移 50627753、SHA-256 `e8b11fbe7f5b7e1f58153eeaebb5c53687a15dfff6175cb0ac82071f3caa67c9`。三个原生字段注册地址及逐列序列化索引保存于目录来源中；全部 33 行解析完成，候选完整类型匹配各只有一份。

当前安装的日期窗口将 2026-10-06 对应到序号 11：排位配置 ID `10011`、通行证配置 ID `202604`、全面战场配置 ID `11`。日期保留为 2026-09-04 02:00 至 2026-11-05 02:00，按本中文安装 UTC+08:00 解析。查询按原日期选择一份当前行，不把最大预置 ID 当作当前赛季，也不改写日期；超出已恢复范围返回原错误。模式 `SOLGameType=1/MPGameType=2` 来自 `ds_common_pb.lua` 条目 6801、偏移 32942080，原始赋值指令 133/134，SHA-256 `6f1bec3a236dbd47c28d932a2702bc8cc386ecb6119312d71d57a62d6e8b8f6b`。

复现：先运行 `work/probe_native_season_bindings.py`，再运行 `work/inspect_season_tables.py --write-catalog`，使用只读原版路径环境变量 `DF_LOCAL_SOURCE_GAME`。查询只读取本地账号；本地尚无已完成排位战局、历史参赛或待领赛季奖励，因此摘要保持未参赛，不虚构积分、战绩或奖励。本修正恢复大厅赛季元数据，不代表排位战局或官方实时排期已恢复。

17:45 启动的独立影子测试中，四次实际 `CSSeasonGetInfoReq` 查询（请求序号 213/253/329/599）均记录 `response_sent=true`、`local_auxiliary_result=0`、`local_season_serial=11`；用户随后确认原大厅 S1 已显示为 S11。该轮保留 1800 秒测试时长，界面确认发生时测试仍运行，尚未将本轮 SDK 恢复记为完成。

2026-10-22 再次报告大厅/排位入口显示 S1 后，核对到最近一轮启动记录属于已退役的 `deltaforce-map-appearance`：其启动时间为 `2026-10-21T17:40:52.593898+00:00`，SDK 观察路径指向该目录的 `work/native-client-tests/1792604501070386400`，该历史版本没有 `native_season` 实现。此记录现保存在本机退役归档中，不作为当前运行源。无游戏进程时，通过 `recover_interrupted_trial.py` 校验原备份和测试提供者哈希，已恢复该轮遗留的影子 SDK；源游戏未改动。

同日从唯一主目录 `deltaforce-local` 重新运行 8 项 `test_native_season.py` 测试，全部通过；沿用现有按原表日期选择赛季的实现，未硬编码 S11、改日期或重置账号。原生验证记录为 `work/native-client-tests/1792640466738972300`，实时服务日志为 `work/elevated-native-trials/1792640466079702400.log`：请求序号 20/114/115/123（模式 1/0/2/2）均实际返回成功、`local_season_serial=11`。自动点击和按键未使客户端离开“前往游玩”页；随后用户手动进入大厅，并明确回复“显示 S11”，完成本轮显示确认。验证后结束本轮客户端，启动器于 `2026-10-22T04:06:29.733075+00:00` 正常退出；最终报告 `record_complete=true`、`original_sdk_restored=true`、`remaining_test_processes=[]` 且无 `test_error`。独立哈希核验确认源 SDK 与影子 SDK 均为 `9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723`，四份测试侧文件均不存在。
