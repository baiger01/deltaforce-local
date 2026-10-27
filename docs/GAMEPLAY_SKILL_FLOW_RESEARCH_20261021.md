# 实际技能释放生产流程：Rush 1009001

截至 2026-10-21 00:56:08 北京时间，本文只读原安装、固定代码缓存和协作者来源，写入本仓库的新研究文件。未启动游戏、读取进程、连接网络、打开数据库或修改协作者及原安装。机器可重放证据：[gameplay-skill-flow-research-20261021.json](../work/evidence/gameplay-skill-flow-research-20261021.json)。本轮核对 175 个来源，既有 connected-v6 的 134 个 pin 全部匹配；重新验证原 EXE SHA256 和 11 个完整连续 unwind 范围。这里的“完整”描述读到的代码范围，不宣称其全部运行语义已经恢复。

后续[首次激活与冷却补查](GAMEPLAY_SKILL_ACTIVATION_RESEARCH_20261021.md)已核实DataSystem对象、两种命令/监听表和template构造虚表，并恢复非正CD的实际选值及数量修改顺序。特别勘误：`0x32e4160`取得DataSystem，不能称为charging getter；旧版由此给首次激活分支起的charging称谓已在下文更正。普通command0与BeginSkill监听byte1走不同表，最后的监听产生/消费连接仍未闭合，不能拼接成完整首次释放。

## 1. 选择依据与结论

研究对象来自实际配置链：`HeroData 88000000025`，UEXP offset `27699` -> `ExpertID 10010` -> `ExpertSkillData 10010`，offset `8429` 的 `SOLSupportSkillID=1009001` -> `SkillDataConfig 1009001`，offset `309289`。既有 `all-schema-authority-coverage-v4` 把该 hero 标为 `unchanged_default_fixture=true`，故不是按 Rush 名称猜一个 ID。**这不是当前玩家仍选择该干员的观察**；冻结 trial `1792478435036855300` 中的医疗干员与本例不同，不借用其对象指针、GUID 或参数。

实际行规定：`SkillStateType=LegsSkill`、`Slot=UIState_SupportSkill`、`CDID=18`、`bIsClientPredcit=true`、`ClientPredictCountFSMEnter=true`、`CDAtStart=true`、`ClientUseCD=0.5`、`UseCD=0`、`ScoreCost=-1`、`bCanRPCEnd=true`、`bRPCEndCastCD=false`、`bCanServerDoTrigger=false`。这些是四个独立域及配置标志，不能拿 Support 的 UI 槽号替代 LegsSkill 或 charging 槽。

配置 instance 是 `/Game/BluePrints/Ability/AbilityAdvanced/BP_AbilityInstance_Rush.BP_AbilityInstance_Rush_C`，真实父类 `/Script/DFMAbility.DFMAbilityInstanceRush`；template 是同目录的 `BP_AbilityTempLate_Rush.BP_AbilityTemplate_Rush_C`。instance Blueprint 的三个函数没有通用激活脚本，不代表该技能无效果：原生构造 `0x808b320` 安装 vtable `0x16f2c530`，写 `TotalUseCount +0x48=3`、`CurrentUseCount +0x4c=0`、`bIsRunning +0x50=false`，实际移动与计数由下面的任务/native 路径执行。

当前服务已实现真实授予、实体 ID、收集模板与初始复制。它仍没有消费首次技能激活、权威执行任务、充能倒计时或效果提交的生产模块。最大剩余工作是接通一次实际释放的状态事务与原生结果；给它发成功 RPC 不会替代这些工作。

## 2. 输入、可用条件与首次请求

新核对的本例入口是 **OnBeginLegsSkill**：原盘 registration `0x186bdad0` 的名字指针 `0x1830ab30` 与 thunk `0xce936b0` -> handler `0xab47d50`。handler 的正常末段 `0xab485f1` 写 event `0x4d`，`0xab485f9` 调 Pawn FSM 分派 `0x4c90e80`。thunk 连续 260B SHA256 `920a66c9d81f2e2562b59238eba3902a5737a8662145f535655925d81f011bcb`；handler 2562B SHA256 `d9f2099837e555df0ae5f4f559e96630ecd93c73a7a2c6a732afda834d2738e8`。早先只研究 Action/Custom 入口，不能直接用它们替代 LegsSkill。本轮没有恢复玩家可改的物理键绑定，不能指定一个键并把它当永久映射。

本地 FSM 的 `UseSkillCheckAction` 活动订阅和正常角色初始化必须先存在。既有 source-qualified `CanEnterFSM 0x3232ca0` 依次检查 checking、技能 `CanUse 0x324ba20`、全局 `CanUse 0x32ff920`、UI 槽 `CanUse 0x326e110`；`CanUseSkill 0x32fce00` 还按 context 的实际 StateType 检查。配置本例禁止死亡、濒死和 SpecialMove/CarryBody/Rescue/Interact/Vehicle/Dive 等状态，并启用消费命令检查。这些静态条件不能证明某次按键时全部通过，不能硬写 checking、权限位或 FSM ready。

正常 `WantUse/WantUseEx` 经 `0x34a7560/0x34a76e0 -> 0x31b38c0` 的 command1/2，形成 `FSkillEventArgs` 后走首次进入/激活路径。已有 [前轮第11节](GAMEPLAY_CHARACTER_RESEARCH_20261020.md) 和 [参数恢复 helper](../work/research_skill_contract_20261020.py) 闭合 30/31/38 的默认值、顺序和递归 grammar；本轮没有重做 codec，也没有取得本例自然首次请求的 wire slice。

- C->S `ServerEnterFSM38` 仅 `skillid`；DFMSkill 的 virtual `0x510` 目标 `0xd5f350` 为空返回，不能以 receipt38 产生效果。
- C->S `ServerActivateState30(skillid,args)`：exec `0x607a4b0 -> virtual0x520 -> 0x341c2b0`，需要当前 context、执行 ID 分支、`CheckSkillOnlyBreak 0x328d320`，再进入 `ActivateState 0x31cc820`。激活正常段 `0x31d1706 -> 0x343ae90` 拷 args 到 context `+0x13c`、Target 到 `+0x28`，随后 `SendFSMEvent 0x32dccc0`、DataSystem 状态分支和 current-skill 更新 `0x3307550`。该对象由`0x32e4160`返回，不能将此段单独命名为charging分支。
- S->C `ServerActivateSucess31(skillid,ExcuteID)` 必须源于真实激活成功分支。失败 `0x3324c20` 的 `max(oldExecID,requestID)+2` 是失效尝试规则，不是成功自增。
- 再按技能且 UsingAbility/Pressed 命令满足原条件时才走 `ServerTriggerBehavior46/RePressedInSkill33`。Fire4、NormalStart0 和 receipt ACK 均不能替代首次激活。

**边界：**已有代码闭合这些分派、context 写入与任务系统目标，但本例 `ActivateState -> BeginSkill 作者状态 -> 每一 task 的运行策略/回调时间` 尚未完全源恢复，不能称为可移植的完整释放执行器。尤其本例配置 `bCanServerDoTrigger=false`，不能把已知 field36 的下游路线当成允许客户端直接提交任意 Rush task 的授权。

## 3. 真正的任务与效果

协作者 connected-v6 已把旧报告仍未知的 receiver 闭合：`GetSkillSystem 0x32fe140` 返回 **SkillSubsystem**，其构造 vtable `0x167f7b08` 的 virtual `0x6c0=0x34e4ca0`；该函数取 `DataSystem +0x370`，调用 virtual `0x2a8`。实际 DFMAbilityDataSystem vtable `0x16cd4d20` 对应 `0x7d82990`，核对 context/template 后转 `TriggerLogic 0x7f389a0`；选中的 task 进入 `DoTrigger 0x7d3b820`、`StartEnterLogic 0x7d54470`，经 `0x7d05f20 -> 0x7d062d0` 的 policy/override 分支调用 task virtual `0x300/0x308`。服务端分支 `0x7d54649 -> 0x31e4090` 记录节点执行时间；另一支才更新客户端记录并发 `RecordOneLogicEnter22`。这与 field36 的参数、GS64 位请求 index、int32 ExcuteID 是不同契约。

Rush 的真实作者收集图有 19 个 task。BeginSkill -> DPVS exemption -> 声音可视通知 -> Buff303019 -> RushSetting -> HandleRush(RushOne) -> NotifyRush -> RushCD -> Buff302003 -> Delay1.5；NormalBreak 另接 CameraModifier 与关闭 exemption。完整参数、callback 名字、task ordinal、UEXP offset 在 JSON `authored`。这些是作者连接和收集结果，不是已经执行的顺序/计时日志。

本轮把收集图之外的实际副作用推进到具体写入：`HandleRush` 的 task virtual `0x300=0x7cbcee0` 解析真实 Character 并调 `0x4461d50`。后者连续范围 14399B SHA256 `7d36dac16c4707fc87ac3f05c6ae9038955d2476388781a4be3497b914049b16`；在正常分支 `0x44642e7` 取 movement 引用，`0x44642f1` 写 movement `+0xe16=1`，随后 `0x44642f8` 调 `0x43f1a90`。同版本 UHT record `0x16661f78` 与 setter `0x5fc8700` 的字节 `c681160e000001c3` 独立证明 `+0xe16` 是 **bWantsToRush**。这证明任务触达真实运动请求，不证明冲刺位移、碰撞、结束/纠正已经在服务执行。

实际 CDO `SettingSOL` 位于 template UEXP `20822`，不是一组凭玩法印象填写的参数。本轮按 tagged struct 重解析得到 `RushTime=1`、`MaxMoveDist=1000` 原生单位、`VelocityXYScale≈0.9`、`ContinueTime≈0.65`、`MoveStopDistance=100`、`MoveStopTime=0.5`、`MoveStopSkill=true`、`bUseGravity=false`、`LimitAngle=30`，并有前后左右路径/高度曲线、方向 Buff 列表、基础 Buff302001/302002、结束 Buff303046。`SettingMP` 的 LimitAngle=40，音效也不同。收集 task7 的参数明确引用 `SettingSOL/20822`。曲线 ObjectProperty 的负索引仍是当前包 import 索引，不能拿来当对象 GUID 或猜资产路径。

`NotifyRush virtual0x300=0x7cca7b0` 核对实例后调 instance virtual `0x3d8=0x7eba5d0`；`0x7eba623` 自增 **CurrentUseCount +0x4c**，`0x7eba629` 调 UI 更新 `0x7f44a10`。UI 运行中显示 Current/Total，不运行时用 literal3/3。因此它不是“还有三次 charging”。

## 4. 消耗与冷却

本轮重新解析完整 `Inventory/SlotCharing` 96 行，找到“动力推进” UEXP offset `80163`、`CdID18`、`ECharingSlot::ArmdedForceItem1`。该行的 **SOL/Intro/Raid/SafeHouse/IrisDiscovery 分支 Init0/Max1/Time20s**；Breakthrough/Conquest 为 Init1/Max1/Time15s；BombDefusal 为 Init0/Max1/Time45s。`UseTime=0`、`CurrentAmmoNum=0`。这些是配置候选值；不能把建构默认的 3/3 或其他模式的15s抄进 SOL。

还完整重解析了 `SlotCharingExtraTable` 109 行和 `SlotCharingByTagTable` 3 行，分别有 36 行与 3 行包含 CdID18 override，完整保存在 JSON。例：map559 的 TacticalConquest_Evolution 条件是2s；KnifeBattle tag 是5s；map446 是 Init1/Max2/7s。**本轮没有本局 mode/submode/map/tag 的实际选择结果及 override 优先级证据，不能宣布20s就是当前局有效冷却。**

既有原生 authority 初始化是 `AddSlotChargingData -> derived0x9802c30 -> base0x34ce810`，按实际选中行的 Init/CurrentAmmoNum 写入并启动倒计时。数值扣减是 `ComsumSlotWeaponNum -> 0x34e1e80 -> 0x355cf70 -> 0x34e3720` 或真实武器分支，再由 derived `0x985db80 -> 0x35537b0` 提交；普通 clamp 与武器计数分支不能混用。

新核对 RushCD task 的 constructor `0x80d35f0`/vtable `0x16fa15e0`，virtual `0x300=0x7cb4630`，本例参数是 `-1.0` 且作者 override `ServerAndClient1P`。正常运行读取 task `+0x230` 的 float，并在 `0x7cb4749` 调 charging `0x34cf1c0(slot,-1,float)`；后者先过 `0x351e5d0` 检查，再取真实 stride `0x1a0` slot record，转 `0x355e320`。因此“进入技能就随意减一再写20s”不足以复现这条路径。后续补查已确认非正时间从slot配置和可能的倍率选值，特定旧timer分支可取剩余时间；数量修改先于timer复用判断，不能据此声称幂等。首次DataSystem状态分支与该task的资格及去重关系仍需闭合，详见补查，不把`-1.0`解释成负一秒或确定的一次扣除。

## 5. 结束、中断与复制

作者终端存在可区分的 callback：Delay task12 的 **OnTrigger** 从 uber entry `2379 -> jump994` 进入 task14 `QA_EndAbility`；其 **OnThen** 从 `2384` 进入 CameraModifier task13。这两条不能合并成固定“延迟1.5秒后统一成功”。后续 Delay task15(0.1s) 的 OnTrigger entry4420 -> mask task16，Delay task17(0.5s) 的 OnTrigger entry5101 -> mask task18。Mask3 是 CanUseSkill/CanStandUp/CanSwitchWeapon/CanSkillSwtichWeapon/CanSkillWeaponFire；Mask2 是 CanAimOn/CanAimOff/CanFire。方向、应用/回收时机需遵循实际 task runtime，不能仅凭列表名强设全局权限。

task14 的 factory `QA_EndAbility` 对应 `QA_AbilityEnd` ctor `0x80de540`/vtable `0x16fb3658`，virtual `0x300=0x7cbbac0`。其正常路径先取 SkillSubsystem、DataSystem+0x370 和当前 skill context，检查 context 后在 `0x7cbbd2c` 调 DataSystem `0x34d26f0(skillid)`；后者继续检查 context、调用 virtual0x2b0 并按角色侧路径处理。本轮 722B 和1901B 的连续代码分别保存哈希和关键指令。instance 的终止 override `0x7f0cd80` 在 `0x7f0ce28` 清 `bIsRunning +0x50` 并调 virtual0x3e0 UI 回调。**这些终端被源定位，但 EndAbility 参数三个 true 的完整语义、异常中断退款/冷却策略及任务回收尚未完全恢复。**

本例 SkillDataConfig 明确 `bBreakByDie=true`、`bBreakByImpendingDeath=true`、`bCanBreakByFire=false`；是否另有间接触发仍需按实际状态处理。NormalBreak 作者分支与 RPC End/重连 End 不是一个统一“取消成功”。C->S `ServerEndAbility37`、`ServerReconnectEndAbility42` 的 wire/profile 与具体 refund/重复语义仍需各自资格化。

真实运行结果通过 owner `SkillState +0x620`、3P `+0x648` 的 Using/ExcuteID/ExcueteDatas/node records 与 UpdateIndexArray 复制。1P OnRep 链 `0x607a330 -> 0x3411770 -> 0x33e4490 -> 0x340e050 -> 0x33d9070` 校对 SkillEntityUniqueID、重建/移除 context、处理 enter/rollback/leave，再调用 DataSystem `0x351f550`。charging 输出还涉及 `Rep_RepCountdownInfo`、`Rep_bEXSkillDone`、`Rep_AbilitySlotChargingData`、ClientSlotDone/NumChange。必须从实际提交的执行、时间、消耗和效果生成这些记录；现有初始 Using=false/ExecID0/空数组及 ACK 不是运行结果。

## 6. 当前生产缺口与最小实施边界

新快照中 [legacy_ds_control_connection.py](../outputs/df-local-server/dfserver/legacy_ds_control_connection.py:1957) 的 `_consume_admitted_actor_packet` 仍只对 ready Pawn bodies 调 owner weapon switch，循环后调 movement；无 skill consumer。该块 SHA256 `26259cfb48769011b28e9793af0ec0e1ba1be82e9c07dc6119e15477f47d1099`，文件 SHA256 `0e6127516565b1d092246ae9931ce5608b9eea53330fe3e3b95c2335db01c837`。独立 field46 codec hash仍为 `221e00a5fa46d82d52389819b6f01eee367d12309fbc8c6ed91bc011e5e9edbf`，没有接到这里。

[skill_template_authority.py](../work/skill_template_authority.py:1) 当前 SHA256 `ce75580df8168215320bc62081a56f11c02295abc50720a41d87466b49e488fe` 明确执行 collection，不执行 gameplay。其 store/graph/callback存在不等于 task tick 或 effect authority。新快照也没有本例 charging state、倒计时、移动/Buff/End事务与上述结果复制。

下一次实现应限定同局已授予的1009001：真实 Name/Outer/GUID、连续可靠 ready body -> 来源限定的首次30请求与args -> owner/entity/context/命令/状态/charging资格 -> 唯一执行ID及作者BeginSkill -> 源任务策略和实际Rush运动/Buff/timer -> 效果/消耗/执行记录共同提交 -> 对应普通复制和成功31。拒绝、耗尽、重复、NormalBreak、死亡和重连分别保留路径。未知的首次连接、task运行策略、移动曲线/碰撞/纠正、哨兵CD和取消策略必须先补证，不得提前发布统一成功或把原生权限位当服务实现。

验收必须在用户实际选择该干员后覆盖：首次可用/未就绪、自然短按/释放/再按、实际位移与碰撞、CurrentUseCount 与 charging独立变化、CD完成、NormalBreak/死亡、重复请求及重连。必须看同局服务事务与客户端效果一致，不能只看图标或执行记录。本文没有进行该原生验收。

## 7. 来源与重放

原 EXE SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`；缓存 manifest SHA256 `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。模板 UASSET/UEXP 分别 `5dd7ee14df09cbdfafa3d40b46e36459f7a2861b4c564d7475923a0ae90d46a6` / `e8cb30a02e28e91b14f7bda32f25781cdbbf893aa403f3adc1eb86b051e8830a`；base charging UEXP `8531b365b5825d05ada8a651f76fc94a80b2ef15c0f2764500b50933f817b908`。所有输入的字节哈希、现存提取链、offset、代码范围/指令、mtime及派生 callback 连接见 JSON；mtime只用于记录读取状态。

从本仓库运行：

```bash
python -B work/research_gameplay_skill_flow_20261021.py --verify work/evidence/gameplay-skill-flow-research-20261021.json
```

本轮已执行以上命令，输出 `replay_matches=true`、`source_pin_count=175`、`old_graph_pins_changed=0`、`native_function_count=11`。helper 只读原盘与 peer，重新解析配置、核对原 EXE/代码缓存并前后重哈希来源；`--verify` 不写文件。显式 `--output` 只允许本仓库 `work/evidence`，本轮使用的文件为 `gameplay-skill-flow-research-20261021.json`。源证据重放匹配证明本文静态推导的可复核性，不证明已完成技能生产实现。

后续独立复核时，旧证据中的 `work/portable_map_bootstrap.py` 已由协作者更新，新增 admission 来源校验作用域；旧文件的 `source_pins` 因而不再匹配。原生函数、配置、作者任务及本文所用收件函数仍匹配。已保留旧文件，另存 [当前源码复核快照](../work/evidence/gameplay-skill-flow-reaudit-20261021.json)，并以新文件为参数重跑 `--verify`：`replay_matches=true`，175个来源pin、11个原生函数通过，既有graph的134个pin仍无变化。本文没有将启动校验优化记作技能执行器已经接入。
