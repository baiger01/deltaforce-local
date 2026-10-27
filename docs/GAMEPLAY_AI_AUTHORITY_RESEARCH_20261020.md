# AI 原生启动与 SOL 巡逻资源补查

本次只闭合一个范围：`AAIController::RunBehaviorTree` 的实际虚调用、游戏派生控制器启动行为树的代码路径，以及 `BT_Group_Patrol` 中一条有条件的巡逻编排。没有启动游戏、服务或进程，没有发包、访问数据库或改动原安装、协作者运行代码/证据。

结论：已经找到真实启动实现和可核对的节点接线，证据超出类名/行为树路径存在。原客户端中的这些实现尚未成为本分支本地服务端的 AI 权威模拟，也没有原生运行验收。医疗和武器报告中的未闭合边界保持有效。

## 1. 可重放来源

- 原客户端：`DF_LOCAL_SOURCE_GAME/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe`，SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。
- 既存只读代码缓存：`deltaforce-map-appearance/work/native-code-cache/1792259162856698600`，manifest SHA256 `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。指令与内嵌代码数据取已校验缓存，UHT/虚表/字符串取原 PE 的只读映射。所有地址均为 RVA。
- [研究工具](../work/research_ai_contract_20261020.py) 验证 23 个代码范围、36 个 PE 数据范围和 39 个指令锚。完整范围、长度、SHA256、UHT 参数、虚表槽及资源字段见 [JSON 证据](../work/evidence/gameplay-ai-authority-research-20261020.json)。标为 branch span 的范围可能跨多个异常展开记录，不冒称一个完整符号函数。
- 研究工具仅输出 JSON。资源解码调用已有 PAK/typed-tag 解析器；纯压缩解码器为安装内 `oo2core_8_win64.dll`，SHA256 `fc923f9bbbf185ca6e853de0e3ebbc81c839323e6e161cd0f75058c60a2b05a6`。仅在内存处理两个选定包，未执行客户端玩法方法，未保存 key 或资源副本。

复验命令，在 `deltaforce-local` 下运行：

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/Scripts/python.exe -X utf8 work/research_ai_contract_20261020.py --assets --compact
```

## 2. 原生调用路径

1. `RunBehaviorTree` 的 UHT `FFunctionParams` 在 `0x1d836ae0`，outer getter `0x13639ed0` 对应 `AIController`。原生参数帧大小 16：`BTAsset` 对象指针位于 `+0`，返回 bool 位于 `+8`；flags `0x04020400`，没有 `FUNC_Net`。这是本地 UFunction，不是请求服务器启动树的 RPC；16 字节也不是网络载荷长度。
2. `AAIController` 原生注册函数 `0x1363bd20` 注册 20 项，表在 `0x1b6f84b0`。`RunBehaviorTree` 绑定 exec `0x1363e210`；它读取 FFrame 的 `BTAsset`，在 `0x1363e287` 调用实例主虚表 `+0x830`，在 `0x1363e29c` 写返回 bool。`UseBlackboard` exec `0x1363eb70` 在 `0x1363ec29` 实际调用 `0x1359b690`。
3. 基类构造函数 `0x135718a0` 在 `0x135718ce` 写主虚表 `0x1b6a6480`，`+0x830 → 0x135945e0`。基类实现会处理黑板、取得/创建 `BehaviorTreeComponent`，再提交树初始化；不是只有空声明。
4. `DFMAIController` StaticClass `0xcdf8510` 的构造 thunk `0xcdf8080 → 0x9c769a0`；构造体在 `0x9c769d8` 写主虚表 `0x17977b48`。该表 `+0x830 → 0x9cf9ff0`，所以同一反射入口在这个派生实例上进入游戏实现。
5. 游戏实现在 `0x9cfa082` 读取 `BTAsset+0x30` 的黑板资产，与控制器 `+0x448` 黑板组件做 `0x13589650` 兼容检查；需要时在 `0x9cfa0b3` 调用真实 `UseBlackboard(0x1359b690)`。
6. `0x9cfa0c5` 调用控制器虚表 `+0x950 → 0x9c9c760`。此 getter 检查缓存 `+0x588`，尝试复用 `+0x430` 的兼容组件；否则选兼容的配置类 `+0x1210` 或默认 `GPAIBehaviorTreeComponent`，经 `0x10ebd0a0` 构造，`0x1270c980` 注册，并写回 `+0x588/+0x430`。默认类 StaticClass `0xebd5c0` 的原 PE 字符串直接确认类名。
7. 组件非空时，`0x9cfa0d4` 置模式整数 `1`，`0x9cfa0dd → 0x13596a50` 调用启动树函数，`0x9cfa0e6` 将资产缓存于控制器 `+0x5c0`。这里确认的是原始模式值；不拿通用引擎记忆替代本构建枚举来源。
8. `0x13596a50` 检查当前实例/资产/运行位。需要启动时，`0x13596ac1 → 0x13597280` 停止旧树，设置 pending 位，写组件 `+0x1f0=树`、`+0x1f8=模式`，再在 `0x13596add → 0x1358ff30` 处理待初始化。
9. `0x1358ff30` 最终在 `0x1359005c → 0x135902f0` 尝试实例化树。后者在 `0x1359043a → 0x1358ae50` 加载树：要求源树 `+0x28` 根节点非空，复制并初始化节点布局；成功路径会到节点回调 `vslot+0x2a8`（`0x135908b6`）和执行请求函数 `0x13592230`（`0x1359099c`）。未继续逆向所有节点算法、执行请求调度与每帧 tick。

除 UHT 直接确认的 `RunBehaviorTree/UseBlackboard` 等名称外，内部 `StartTree/ProcessPendingInitialize/PushInstance/LoadTree` 标签是根据指令体与调用关系做的语义定位，不声称拿到了原始 PDB 符号。

### 返回值的实际边界

- 空 `BTAsset` 在 `0x9cfa066..0x9cfa076` 返回 false。
- 组件为空时，`0x9cfa0cb..0x9cfa0ce` 跳过启动调用，但函数仍可能保留此前的 true。因此 `RunBehaviorTree==true` 不能证明树执行或 NPC 已开始巡逻。
- 启动调用没有向上返回实例化成功结果；`0x1358ff30` 还会在组件 `+0x2a3` 的 bit2 置位时保留待处理状态。树加载、AI system/world、黑板兼容等下游条件也可能失败。
- 游戏函数含可覆盖控制流的可选 instrumentation 分支。本次没有读取这些可变标志，不能断言一次真实运行采用了哪个分支。此静态调用路径本身也不证明服务器权威角色、当前关卡模板选择或网络复制已接通。

## 3. 原始巡逻树的实际编排

这次没有停在旧目录索引。只读解码安装内 `pak-0-1-pakchunk73-WindowsClient.pak` 中路径 `BluePrints/Characters/AI_SOL_V2/Drama_SOL/Patrol/Common/BT_Group_Patrol` 的两个载荷，PAK 主/次索引与两个载荷的 compressed SHA1 均通过：

- `.uasset`：encoded offset `5576`，物理 offset `10985472`，30,480 字节，SHA256 `d60ff7f5f8d1fce4d58fefa20c9e9dab0d6454da3e1e67c36e7538dd23954f62`。
- `.uexp`：encoded offset `5600`，物理 offset `10991353`，40,308 字节，SHA256 `3af128804f38b30015802350a86f68b85f7820b3d3189a17db0d87f170ec749f`。
- 解析 147 个 export、109 个 import、506 个顶层 typed property。完整导出连续 extent、UEXP 尾 magic、85 个有序 child 与各目标 `ParentNode` 的引用关系均校验通过。BlackboardKeySelector 的嵌套 tag 完整消费；未序列化字段保留为未解析默认值，不补造配置。

根 export `1` 的 `RootNode` tag 位于 UEXP `0`，值为 export `29`；`BlackboardAsset` tag 位于 `29`，值 `-3`，完整 import 为 `/Game/BluePrints/Characters/AI_SOL_V2/BB_SOLAI_V2_Template.BB_SOLAI_V2_Template`。这证明该资产的引用，并未解析该外部黑板的类型、初值和当前实例值。

以下是按序列化 `Children` 数组顺序核实的一条路径，child 索引从 0 开始：

1. 根 `29 / BTComposite_Sequence_5` 的 child 5 指向 `12 / BTComposite_Selector_3`。根的先行 child 0..4 还有领取任务、战斗状态、视锥、聚焦和另一 selector，不能跳过它们宣称必定到达巡逻。
2. `12` 的 child 1 指向 `27 / BTComposite_Sequence_3`，挂 decorator `75 / BTDecorator_JobIsFinish_C_1`。该 decorator 在 UEXP `25913` 开始：`AIJob.SelectedKeyName=AIJob`、`ObservedKeyNames=[AIJob]`、`bInverseCondition=true`、`FlowAbortMode=EBTFlowAbortMode::Self`。这些是真实配置；`JobIsFinish` 的 Blueprint 判定算法未恢复，不能由名称自行定义“完成”的条件。
3. `27` 的 child 0 是集合分支 `19`，挂 ForceSuccess `56`；child 1 指向 `23` 并挂 `76 / BTDecorator_Loop_0`，在 UEXP `26228` 明确序列化 `bInfiniteLoop=true`。
4. `23 / BTComposite_Sequence_17` 的 child 0 指向 `21 / BTComposite_Sequence_15`，挂 ForceSuccess `58`。`21` 的 NodeName 实际为“行走”。循环/ForceSuccess 的类名与资产字段已确认，实例调度和装饰器算法未在本地实现。
5. `21` 的 child 0 指向 `143 / GetGroupPatrolAssemblePoint_C_1`，其真实类 import 是 `/Game/BluePrints/Characters/AI_SOL_V2/Drama_SOL/Patrol/Common/GetGroupPatrolPoint.GetGroupPatrolPoint_C`，UEXP extent 从 `38827` 开始。序列化键为：`AdjustedLocation=G_WanderCenter`、`TempTargetLocation=Temp_TargetLocation`、`KPCenter=G_DestinationPos`、`PatrolJob=AIJob`、`FucosPoint=Temp_DirectionVector`、`Staytime=T_TimeRemain`、`Pose=MovePose`、`RandomStartTime=Alert_CoverTime`；NodeName 为“获取巡逻点 朝向”。这些字段名和键绑定不等于已经证明任务读/写方向或选点算法。
6. `21` 的 child 4 指向 `126 / DFMAITask_AdvancedMoveTo_5`，真实类 `/Script/DFMGameplay.DFMAITask_AdvancedMoveTo`，UEXP `33742` 开始。`TargetLocationBBKey.SelectedKeyName=G_WanderCenter`，与任务 `143` 配置同键；`bStopOnOverlapNeedsUpdate=false`，services 按序 `[83,82]`。child 1..3 的其他节点必须按树实际结果先行，不能将 143 和 126 画成无条件连续调用。
7. 服务 `83 / BTService_GroupPatrolUpdate_C_2` 配置 `ScalerOffset=0.10000000149011612`、`AIJob=AIJob`、`KPCenter=SelfActor`；服务 `82 / BTService_GroupPatrolRandomFocus_C_3` 配置 `MovingDir=Temp_DirectionVector`、`Interval=1.0`、`RandomDeviation=0.25`。没有解析其 Blueprint 算法和未序列化 CDO 默认项，也未证明本局调度过这些服务。

上述节点、条件、参数原始 tag offset 与值保存在 JSON 的 14 个 `selected_exports` 中。全 147 个 export 的确定性解析摘要 SHA256 为 `6b4882188e4ab72a918066a725bdbbfbdfbfe87310e93eaea86e8675e273fe55`，可由研究工具重放。

## 4. 本地接入与下一步

本分支 `outputs/df-local-server/dfserver/match` 仍是战局诊断、有限票据准入及不可用响应：`legacy_ds_match_admission.py:1` 明确无 network/gameplay work，`native_match_unavailable.py:13` 处理 `CSRoomMatchStartAllocReq` 并返回 maintenance/disabled。本次只读复核的 81 个 canonical Python 模块无 `RunBehaviorTree/BehaviorTree/AISpawnChecker/perception/patrol/ai_actor/ai_spawn/npc` 接入引用，目录 manifest 与三个 match 源文件 hash 已记录。关键字阴性只是辅助证据，不能独立证明所有外部可执行实现都不存在。

可以据此把“AI 只知道类和树名”的结论提升为“已恢复一个实际树启动路径和一条原始巡逻资源编排”。仍不能提升为本局 AI 完整可玩：

1. 继续本条来源时，先只读恢复外部 `BB_SOLAI_V2_Template`、`GetGroupPatrolPoint`、`JobIsFinish`、两个服务的 Blueprint 实现/CDO 默认项，再追 `DFMAITask_AdvancedMoveTo` 如何使用黑板目标、导航请求和完成回调；不能填造选点、目标可见或节点成功规则。
2. 本地实现必须明确为独立服务器 policy：选择来源明确的 Pawn/controller/template，建立服务器 AI 时钟、黑板/状态机、导航/碰撞、感知、目标选择、武器/弹药/射击、命中/护甲伤害、死亡/掉落。恢复客户端协议和设计这些权威规则是两个需分别验收的工作项。
3. 原生接入还需当前实例真实 ownership、Actor/subobject/ClassNetCache 与移动/生命/伤害/死亡复制协议。当前树的 `RunBehaviorTree` 非网络 RPC，不能作为客户端发请求的 wire 契约。
4. 未来原生验收须独立观测同一 NPC 的初始化、条件/黑板变化、连续移动、可见/不可见目标分支、一次合法开火/弹药消耗、服务器命中与伤害、死亡和有限掉落；`RunBehaviorTree` 返回 true、出现 Actor 或资源解码通过均不能替代这些结果。本次没有执行该验收。
5. BOSS、队友救援、多人和其他模式没有由本条 SOL 巡逻路径闭合，继续保留独立缺口。[原战斗报告](GAMEPLAY_COMBAT_RESEARCH_20261020.md) 的医疗协议、权威消耗和结果边界未被本补查覆盖或改写。
