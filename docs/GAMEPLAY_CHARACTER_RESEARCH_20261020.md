# 角色、移动、体力与技能接线复核

初稿研究截止：2026-10-20 07:17 UTC（北京时间 15:17），07:21:33 UTC 曾复核33份来源均未变化。07:42:59 UTC 再次只读复核发现移动 runtime 的源码资格检查已更新，07:44:36 UTC 又发现其新增guard依赖有指纹比较修订，原试验观察与旧版本哈希保留。08:24 UTC 的61份pin均匹配；field46追加见第9节。09:11 UTC 再读发现5份运行来源变化，第3节已撤回其旧“当前”结论；当时首次技能边界见第10节。10:05 UTC 已从构造、属性链和serializer闭合30/31的源推导参数grammar，第11节取代第10节对应未知；SourceGuard再次漂移仅记元数据，不推定行为。本轮只读 `deltaforce-map-appearance` 的源码、原安装的固定镜像及已有缓存/冻结试验文件；未启动游戏、接触运行进程、发送报文、读取生产数据库或修改协作者文件。来源逐字节哈希与版本历史见 [JSON 证据清单](../work/evidence/gameplay-character-research-20261020.json)。这是具体接线审计，不是功能验收。

源码根：`historical map checkout`。原生镜像 SHA256：`4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`；只读代码缓存 manifest：`dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。原始文档 [MAP_SYSTEM_RESEARCH](../docs/MAP_SYSTEM_RESEARCH_20261018.md)、[MAP_PLAYABLE_RECOVERY](../docs/MAP_PLAYABLE_RECOVERY_20261018.md) 已通读，以下以当前实现和试验 `1792478435036855300` 更新其中旧状态。

## 1. 本轮最重要的边界

- 出生、控制权、账号干员/外观、基础 HUD、技能身份、技能实体、GS 动态能力组件、模板收集与模板初始复制确有接线。不能继续称为全都只有空组件。
- 当前主 FSM 的通用 `IsInitialized=true`、`R_bHasStarted=true` 已观察；角色专用 `bFSMIsInited` 的**声明与 h6 已观察，实例值没有采样**。两者不能混同。当前生产投影只发 context、组件实例引用、started，没有 h6。
- 当前技能主表 11 项、槽表 5 项；1030003 的 context 已从前轮 type0/spawnstate1 变为 type4/spawnstate2，真实 instance/template 弱引用可解析。旧的“主技能没有模板、类型全部未完成”不是最新结论。
- `bIsCheckingSkill=false`、技能 Using/执行记录为空仍是冻结观察事实，但它们不能唯一定位失败。当前服务没有技能激活、取消、任务效果、充能扣除或冷却运行时分派。
- 移动已接入拥有者通道与普通 `NewServerMove` 的受限位置接纳。其输出是服务本地位置主张验证，不是碰撞重演、运动模式模拟、纠正/移动 ACK、奔跑或体力权威实现。

## 2. 出生与所有权

### 已证实的来源和当前接线

真实 `SOLStartSpotTemplateTable`、GameplayConfig 的 TeamStart/PlayerStart 经 `ms23-spawn-schema.json` 固定，schema SHA256 为 `1d849b047eeddc72ce7e3852734ca75bcbae4bb7249ec4a7e512bd9ac6c8a8a1`。`legacy_ds_ms23_spawn.NativeSpawnRandom` 移植缓存中 `0xc404400/0xc41f820/0xc41f920` 的正常 RNG；`allocate_ms23_one_participant` 执行方向/分组打乱、等价正权重模板抽取、容量抽取、分组选择和 float32 距离排序。它**显式只支持首个单人、未指定点/模板的正常 MS23 子集**，保留等价模板集，未伪称已恢复精确 RowMap 选择顺序。参见 [分配器](../outputs/df-local-server/dfserver/legacy_ds_ms23_spawn.py:103)。

`portable_map_spawn_selection.spawn_selector` 把本局 ticket 的 seed、player_id 与明确的本地 team_id=1、team_index=0、MapLevel=0 策略绑定；`portable_map_bootstrap.resolver` 从同次分配替换 Pawn manifest 的位置和朝向并保留完整导出。PC/Pawn/PS 的普通引用、Role 接收重映射、ClientRestart/接管确认、ClientSetRotation、HUD、RealStart 各有现存阶段依赖。[接线](../work/portable_map_bootstrap.py:307)、[单人策略](../work/portable_map_spawn_selection.py:12)。

原生历史验收已支持 WASD 方向正确、外观可见和基础 HUD；这不证明每个随机出生点可落地。碰撞修正、地面/胶囊安全、移动基座、多人队伍分配、死亡复活/重部署未实现。当前 allocator 自身也输出 `native_collision_adjustment_applied=false`。

### 完整闭环还缺什么

大厅选择/携带冻结 -> 同局 seed/出生分配 -> Pawn/PC/PS/GUID/owner -> 原生接管 -> 服务 `AcceptedPositionState`，这部分有连接。出生安全应先由本地权威确认实际地面和胶囊空间，再种子化位置；不能以客户端交互报文坐标重置服务位置。新 Pawn、重连代际或合法时间戳重置必须显式 reseed；现代码不支持死亡重生位置与状态重建。

出生不直接修改账户。局内位置、姿态、体力、技能实例应属该局；结束时只有确认的物品消耗/产出及结算规则进入账户事务，不能把本局技能 ID ledger 当作账号技能拥有状态。

## 3. 普通移动与扩展运动

### 确切输入和接收格式

当前真实默认组件为 `CharMoveComp`，类 `/Script/SOL.SOLPlayerMovementComponent`。本局实际分配 GUID 从 admitted manifests/plans 提取，不固定历史 GUID。真实 ClassNetCache 声明 `NewServerMove` index6、exclusive maximum10；UHT flags `0x80220c40` 为 **C->S unreliable**，原生 248B `GPMoveParams` 不是 wire 大小。C->S 内容没有 S->C stable-name selector 位。[绑定](../work/portable_movement_binding.py:67)。

原生 `0x5fc6670 -> 0x4d11810` 的完整连续函数范围 1235B，code SHA256 `aebfae7274d9d5799536ae70aeae85806e42e045a49f2f1d31cc7dbe41a26018`。依次为 struct presence、timestamp f32、packed10 acceleration、MoveFlags u32、View u32、packed100 location、roll u8、move number u32、packed mode u8、packed100 velocity、extension flags u8。普通 decoder 全量读完且要求准确 EOF。[线格式](../work/portable_movement_wire.py:141)。

接收链是 `GameServerProbe` 的 admission_movement_factory -> `legacy_ds_movement.set_profile` -> `_consume_admitted_actor_packet` 的 Pawn ready bodies -> `portable_movement_runtime._moves/accept_position` -> clone 中 position/revision 原子提交。每次检查确切 ticket、peer、transport、generation、Pawn 通道、源哈希及已有组件 metadata 的投递门槛。[运行时](../outputs/df-local-server/dfserver/legacy_ds_control_connection.py:1954)。

07:42:59 UTC 的源码复核：`portable_movement_runtime.py` 从初稿/原试验封存的 `0f1e849906bbdce143f4ef483203fb6acebef5330d410309ae05dc3d2512faa2` 变为 `c51190cb45e03d98973a6cb09f94fb0296501f8cd90300f88eb23f7b9ca7aa7a`。新代码将 sources_current 从每次完整重读哈希改成 [SourceGuard](../work/portable_source_guard.py:47)，并把该新依赖纳入source pins。Guard构造时验证SHA256；Windows上保留FILE_SHARE_READ句柄以阻止写入/删除/重命名，调用时检查文件与句柄身份，非Windows仍重读哈希。07:44:36Z再次读取的guard hash为 `4a8cbc45919a8da92568ae2783326826170a12a5a2e718a0d7bee445985fee12`，它分别保存fstat/path.stat指纹并各自复核，替代07:42时的单一指纹比较。两次都只改变源码冻结/资格检查方式，没有新增移动玩法、reason journal或gap预算修正。原生试验的884项封存仍记录旧runtime；本轮未取得新guard的原生性能或功能验收。文件系统mtime为runtime 07:39:04.070835Z、guard早期版07:41:22.717283Z/当前版07:43:00.202596Z，仅作为读取到的文件元数据，不据此推断准确修改过程或试验是否运行。

当前明确本地策略为 max_speed=1500、max_client_delta=2s、skew=5s、tolerance=2，接受全部 0..255 packed mode 字节；这不是恢复了 256 种原生运动语义。`MoveFlags` 也仅解码保存，未执行姿态/跳跃的语义。

### 运动类别的真实覆盖

- **走/跑**：零扩展的普通位置可能接纳。服务没有 acceleration/摩擦/坡度/速度积分、奔跑状态或 stamina tick；可动不等于可跑。
- **蹲/趴/跳**：原始声明确有 `MaxStepHeight_Crouch +0xea8`、`MaxStepHeight_Prone +0xeac`、`CacheTakeoffBaseForJump +0x13b0`、`VerifyJumpInfo +0x1128`。当前来源没有把它们与 MoveFlags 位或 packed mode 值闭合；不能声称某位代表某动作，也不能断言这些动作必带扩展。零扩展即使解码成功，也没有权威胶囊/起跳/落地/姿态复制。
- **滑铲**：真实 `bWantsToSlideTackle +0xe12`，干员 detail 另有 CanSlidingTackle；两者不是同一字段。当前不执行滑铲允许、冲量、摩擦、退出或体力消耗。
- **翻越/攀爬**：真实 `bWantsToVaultOrClimb +0xe10`；`GPMoveParams.VaultPayload +0x58` 确有独立扩展分支。凡请求使用 extension bit4 的 VaultPayload，当前直接拒绝。不能将所有 climb 都未经证据归成同一 payload。
- **游泳/水上冲刺/上下潜**：真实 `bWantsToSwimmingSprint +0x997`、Up +0x996、Down +0x995，`SetSwimmingUp/Down` 为本地普通函数声明；当前服务不做水面、浮力、出入水、氧气或游泳速度状态。mode 字节被允许不代表游泳实现。
- **移动基座/骨骼**：原生 extension bit1 选择 ClientMovementBase +0x40 和 ClientBaseBoneName +0x48，当前拒绝；需要真实已加载基座 GUID、FName 和相对变换校验。
- **其他 custom/扩展**：bit2 为 CustomIndex +0x50，bit8 为 ExtensionData +0xe0；这些和未知非零位均拒绝。准确读取位置在 `0x4d11b61/0x4d11b83/0x4d11bbb/0x4d11c7a`。不能把“普通 decoder 支持”扩写成全部运动支持。

上述属性来源为 [UHT movement declarations](../work/evidence/map-system-audit-20261018/ai-runtime-research-20261020-world-movement-owner-functions-v1.json)，hash `ecb70137ed2b71bb1aa128c3f368ea0ae1a3c1b2a8e7339b875c4b22a7ed6dc9`；结构偏移来源 [GPMoveParams](../work/evidence/map-system-audit-20261018/ai-runtime-research-20261020-world-movement-params-fields-v1.json)，hash `55ac2fdc6b77f0092f960a594dc2cfbd6a8d678bc4d0d1d2b0398a8f44921bf1`。声明和偏移本身不证明函数行为。

### 必须先修的可观测性和接收缺口

历史08:24版本的 `portable_movement_runtime.consume` 捕获所有 ValueError 后仅计 `movement_rejected`。09:11再次读取的新版本已返回封闭 `reason_code`，`legacy_ds_movement`维护 `movement_last_reason` 与饱和计数，故撤回“当前没有原因分类”的说法；新生产链还引入 `portable_movement_clock_epoch.LocalClockEpochPolicy/accept_packet_moves`。本轮只核对这些变化存在，未对新epoch策略做功能验收，也未确认它已保留逐请求decode offset、extension byte、delta/skew/距离摘要。后续应以**该次实际 Pawn/component GUID**的私有有界证据离线重放；不能把transport拒绝、opaque RPC、扩展、时钟、速度混为一类。

历史受限 `allow_receive_gap` 分支能恢复较大时间差但位移预算仍钳在 max_client_delta；拒绝不推进状态。主会话“10s gap 后移动50m再持续拒绝”针对该旧分支，这是离线可重现边界，**没有证明它就是实机大量拒绝原因**。新epoch模块已接到runtime，因此旧“当前没有gap/reset处理”不能直接沿用；其实际策略需独立审计与验证。新runtime hash `2b0a80f96a8f73995a5b6b98b6a015df680415bcccfb8f76ae7d31d7d06b6995`，新epoch模块hash `fe48e344e1d4988645f8e7555685c73661b76d7c9972b0f82ae89d6a2fd0f287`。普通预测纠正/移动ACK与完整运动语义不由该模块存在自动成立。[历史预算代码](../work/portable_movement_wire.py:271)。

## 4. FSM、Sprint、体力、生命 UI

### 角色就绪门不能由 generic 标志替代

最新冻结 `owned-fsm-metadata.json` 的 `IsInitialized +0x6d4=true`、`R_bHasStarted +0x664` packed=0x0f、RootStatePathGuidArray count200，均已读到。root path 列表不是本地活动节点列表。Blackboard 的 `bIsCheckingSkill +0x389=false`，+0xd98 输入阻挡 bitarray 的118个used bits全零、first_set=-1。[观察](../work/native-client-tests/1792478435036855300/owned-fsm-metadata.json:65848)。

作者 MainInit->Sub 的 Kismet 条件读取 `bFSMIsInited`，UEXP serialized offset88350、memory entry22243。该字段位于角色 FSM 实例 +0x728，**是 Net、无 RepNotify**；UHT record `0x1669b1e8`，record hash `da351719a91792f9139bdcd0c5752a872a61451ba71f642098b3628f0a7bd0ed`。最新普通布局为 h6/opcode21，不能用 CNC index5代替 h6。[UHT](../work/evidence/skill-flow-research-20261020-v1/native-gp-fsm-networkbase-uht-v2.json:60)、[实际 layout](../work/native-client-tests/1792478435036855300/owned-fsm-metadata.json:65566)。

正常 `GPFSMInstance.InitCharacter 0x48a1ed0 -> base 0x48a2090` 先绑定当前 Pawn、Blackboard、GPIdentity 和事件 delegates。base尾段 `0x48a28fa` 检查 Identity 指向对象 +0x100；为0则经 virtual0x438 初始化 databoard。`0x48a2917 cmp byte [identity+0x102],0`，`0x48a291e je 0x48a2928`；只有 server身份非零才在 `0x48a2920` 写实例 +0x728=1。2281B 连续 unwind 范围 code hash `b2fb0878d14516f794e5164b20c203a309928faa304e7ad75edc61ed025d1c2a`，报告自身不宣称完整语义全部恢复。[原条件](../work/evidence/skill-flow-research-20261020-v1/native-gpfsm-inited-writer.json:3483)。

当前 [project_updates](../work/portable_fsm_replica_initialization.py:119) 仅三个阶段：实例 context h1 -> 组件 R_Instance h4 -> 实例 started h5。**h6没有生产者，最新实例值未读，故保持未知。** 正常网络接线应先完成本地权威的角色/context/identity/databoard与作者状态初始化语义，再用该当前实例的普通 Net h6发布实际就绪状态，由客户端既有 tick/条件进入子图；不能直接改进程 +0x728、bIsCheckingSkill、内部 initialized 或 permission bits。仅发送 h6也不证明这些服务语义或下游子图已成立。

第一轮有界观察应增加当前 typed Main_C 的 h6值、GPActor/GPIdentity/Blackboard/GPCharacter引用，Identity 的 databoard/角色侧状态，以及源资格齐全的本地 active node/runtime容器、referenced子FSM context和 UseSkillCheckAction/Sprint动作订阅。不要用网络 `R_ActiveStates` 为空判定本地无节点。`UseSkillCheckAction.OnEnter 0xabba470` 的正常写入在0xabbeceb，OnExit0xac1e510在0xac22cf6清除 checking。

### Sprint 与体力

真实输入链：`0x4eeb740` 的 UGPInputMovementLogic消费者 -> Blackboard和源输入阻挡 -> Character入口0x4baf010 -> GPSprint.CanSprint0x44c1a70 -> 已绑定 StaminaData、疲劳许可、CurrentOverrideMovementInfo和 MovementLimitConfig -> 作者外部Sprint状态的 SprintCheckAction/SprintExecuteAction。作者 AlwaysFalse轮询条件不排除独立 event transition，事件7/8/6经 Pawn.OnFsmTransitionEvent评估；不能据一个false条件删改状态图。

最新 `owned-vitals`：Sprint Owner/GPOwner/Blackboard引用指向当前Pawn；registered、created、BeginPlay已成立。Sprint generic initialize位false是已核对的派生override边界，不能据此强设。实际 Stamina/MaxStamina=100/100，StandBasicSpeed=340、SprintBasicSpeed=605、RuntimeMaxSpeed=1500、EnableSprint=1、LockSprint=0、Moveable=0；后二者为原生构造默认，不是可凭名称改写的开关。CurrentOverrideMovementInfo=0004、疲劳允许true。已知值未识别出CanSprint拒绝，**没有实际调用返回或按Shift瞬时状态证据**。

现服务只发送 vitals metadata 空块，不提供 stamina 消耗/恢复权威tick、阈值/疲劳变更或速度Buff。还要核对GPSprint tick0x4f44990、正常输入起跑分支0x4ef1118/1125/112e/1137/114b、ActorComponent活动/tick开关、按下与释放时作者状态事件、bWantsToSprint和速度/体力时间序列。`ServerEnterSuperSprint` flags0x220cc0是server RPC，不是服务向客户端授予跑步的消息。消耗率、延迟恢复、负重/伤害/姿态修正及对应实际字段尚未从当前证据恢复，不能填猜测值。[Sprint/Health边界](../work/evidence/model-init-chain-20261018/native-sprint-health-repair-boundary-v2.json)。

### 生命与血条

最新真实 Health/MaxHealth=100/100，Shield/MaxShield=0/0，Pawn.MaxHealthBase=100。既有原生主条公式为 `ViewData.CurHealth / (boundPawn.MaxHealthBase + ViewData.CurShieldHealth + epsilon)`；MaxHealth<=100分段分支保留正常比例，未找到固定0.5系数。需读可见Widget绑定Pawn、BloodBarDataView CurHealth+0x10/MaxHealth+0x14/CurShieldHealth+0x1c、平滑值+0x3ec、最终百分比+0x3a0及模式分支。不能把半条画面修成200HP。当前也没有权威伤害/治疗/死亡生命事务，属性构造默认不等于战斗实现。

## 5. 技能实体、模板与当前已完成部分

真实选择链为 `ticket.selected_hero_id -> HeroData.ExpertID -> ExpertSkillData.SOL*SkillID -> SkillDataConfig/AbilityInstance/AbilityTemplate`。`SkillHelperTool.lua` function0.0原行12-16与模式特定UI消费者有独立源块 hash `e92c49418b6c83d43e2c7c024db277c840c8273eafa5855a118dbc0d87843500`，不能把HeroID当ExpertID、UI slot当StateType或charging slot。[Lua证据](../work/evidence/skill-flow-research-20261020-v1/baseline-skill-input-ui-lua.json)。

当前生产链：实际 ticket/快照 -> `prepare_grant` 校验同局身份 -> 持久signed32 entity ledger保留实例ID -> 同个ordinary更新内detail h4/5/index h6 -> `SkillState h141`初始真实条目 -> 原生OnRep创建/核对实体 -> GS正常动态组件 -> `SkillTemplateAuthorityStore.materialize`执行真实作者**收集阶段**并提交graph/seeds -> template/index普通复制 -> 客户端正常构建模板和pending context回放。[工厂](../work/portable_map_bootstrap.py:741)、[初始SkillState](../work/skill_initial_state_values.py:119)。

`skill_template_authority` 的自述及实现都是 collection，不执行战斗效果；SQLite保存的是admission绑定收集图/种子与请求编号。`reserve_request_index`的GS步进+3，失败技能的int32 ExecuteID失效规则+2及entity ID是三个不同域。当前实际index字段为FInt64Property，不能继续沿用旧报告“FUInt64”声明。[存储](../work/skill_template_authority.py:734)、[真实类型校验](../work/skill_template_replication.py:1)。

最新冻结观察：SkillState11、SkillEntityMap11、SlotMap5，LocalAbilityInstances头count6；1030003/4008007/6010100/1030004/1030009/4008010的相应configured引用已有可解析instance/template；1030003 type4、slot1、spawnstate2。3012006与4008009仍type0/spawnstate1，不能忽略；无configured instance的某些技能弱引用未解析不能单独视作失败。全部11个Using为0，ExecuteID为0、ExcueteDatas为空。后者只代表观察时状态。[具体实例](../work/native-client-tests/1792478435036855300/owned-skill-entity-metadata.json:104989)。

## 6. 技能输入到效果：真正未接的部分

### 请求、权限、取消与执行

本地BeginActionSkill thunk0xce93050 -> handler0xab440f0，Custom2/3对应0xce93160->0xab44b00、0xce93270->0xab45510；UseSkillCheckAction的活动订阅、FSM event0x4c90e80是输入前提。`CanEnterFSM0x3232ca0`依次需要checking、技能CanUse0x324ba20、全局CanUse0x32ff920和UI槽CanUse0x326e110；`CanUseSkill0x32fce00`经context+0x90检查类型。旧日志 `invalid SkillStateType 1009005`中的整数是SkillID，不能据此编造enum修复。

`WantUse/WantUseEx`经0x34a7560/0x34a76e0到0x31b38c0的command1/2，结构`FSkillEventArgs`原生84B；本地指令/84B内存并不是可直接发送的网络记录。

已核验RPC方向和入口：

- C->S `ServerEnterFSM` field38，int32 SkillID；当前DFMSkill virtual0x510目标0xd5f350为空返回，不能把接收它当技能效果。
- C->S `ServerActivateState` field30，SkillID + SkillEventArgs；exec0x607a4b0 -> virtual0x520 ->0x341c2b0，context校验、可选ExecuteID hook、CheckSkillOnlyBreak0x328d320、ActivateState0x31cc820。
- 激活0x31d1706->0x343ae90拷args到context+0x13c、Target到+0x28，随后SendFSMEvent0x32dccc0、选定充能分支及current-skill更新0x3307550。实际节点/任务/效果提交仍需单独实现。
- S->C `ServerActivateSucess` field31 flags0x1020cc0，尽管名字带Server；它只应在真实ActivateState成功分支后产生。失败0x3324c20用`max(oldExecID,requestID)+2`失效尝试，不是成功自增算法。
- S->C `RPC_CastSkillFailed27` / `RPC_CastSkillSeccess28`分别到0x33f03f0/0x33f0a80；C->S `ClientExcuteDataAck`也不能按名字猜方向。
- 重复按键 `ServerTriggerBehavior46/max98`，真实 `ESkillBehavior.RePressedInSkill=0x21`，NormalStart=0；路径0x607b3e0 -> DFMSkill0x342bbd0 ->0x3316dd0 ->0x3315ec0。它不能替代第一次激活。
- `ServerDoTrigger36`参数SkillID/LogicID/type/index，经0x341f080 -> GetSkillSystem0x32fe140 -> 返回对象virtual0x6c0。后续新证据已把目标缩到0x34e4ca0，272B codeSHA `57b89941d9e0dce891e17840850d70afa5bbb9e2c7776fd30805c02272eb23e8`，其正常路径仍调用下一级virtual0x2a8；必须继续核对真实接收类和目标，不能调用错到DFMSkill组件。

本轮读到的 `owned-skill-rpc-layouts-v2.json` 已自然取得field46的真实existing FunctionRepLayout：两个parent，skillbehavior opcode6/native offset0、SkillId opcode5/native offset4；旧综合v4称46未观察已过时。前五项27/28/30/31/38仍因UFunction serial0而不可查询；这**不证明layout不存在或RPC从未发生**。不得调用会分配serial的getter、伪造(index,0)key或用UFunction*代替weak key。该冻结v2的`rpc_parameter_codec_recovered=false`只描述当时观察文件；08:19 UTC 已核对协作者后续独立codec和具体serializer，field46参数格式已闭合，第9节取代“仍须恢复46参数codec”的旧结论。[RPC布局](../work/native-client-tests/1792478435036855300/owned-skill-rpc-layouts-v2.json)。

`_consume_admitted_actor_packet`目前只分派PC启动/库存就绪、owner weapon switch与movement；未知skill内容留作opaque receipt。没有任何技能authority consumer，传输ACK不会运行上面这些函数。取消/中断还有 `ServerEndAbility37`、`ServerReconnectEndAbility42`及behavior/执行leave分支，但其参数线格式、正常取消refund/冷却策略和执行副作用未闭合，不能先发统一成功。

### 充能、冷却、消耗

四个域必须分开：Hero SOL role slot、ESkillUISlot、ESkillStateType、ECharingSlot。真正连接字段是SkillData配置的CdID。真实 `SlotCharing_CombinationTable` UEXP hash `b13bc541c7e0f088286affe93a46c067fa0c3283fdc613cb85801d0b8881e4f4`：医疗粉尘offset45/CdID88，SOL Init2/Max2/35s；遥控烟雾offset4305/CdID89，Init2/Max2/40s；救援无人机offset8541/CdID90，Init0/Max1/120s。完整覆盖22行和另三张override表已有证据；按mode/submode/map/tag选行和当前实际实例值仍需核验，不能跨模式抄一套数。[表行](../work/evidence/skill-flow-research-20261020-v1/closed-skill-source-evidence.json:67)。

正常Authority初始化 `AddSlotChargingData -> derived0x9802c30 -> base0x34ce810`；0x34cf0a8按row.Init、0x34cf0b6按CurrentAmmoNum初始化并启动倒计时。消费链 `ComsumSlotWeaponNum ->0x34e1e80 ->0x355cf70 ->0x34e3720`或真实weapon分支0x35655a0，derived0x985db80到0x35537b0提交。普通计数clamp(Num+delta,0,Max)，正向溢出按配置进AmmoNum；武器支持槽不得套同一规则。

`0x35537b0`比较旧/新total，扣减前调用virtual0x450，再写Num+4/AmmoNum+8和正常回调/复制通知；0x34e1e80也经0x6085ce0发ClientSlotNumChange。UI读GetSkillNum0x32fb080、GetCDConfigTime0x32e5450、GetCDRemainTime0x32e5570；复制端涉及Rep_RepCountdownInfo、Rep_bEXSkillDone、Rep_AbilitySlotChargingData和ClientSlotDone/NumChange。当前服务**既未构造权威charging state，也未运行倒计时/扣减/恢复或发布这些结果**。[闭合原生路径](../work/evidence/skill-activation-authority-20261020-v1/connected-skill-activation-source-v4.json)。

### 投掷/射出、Buff与真实效果

35个配置instance package已恢复，空Blueprint wrapper可能继承真实native gameplay，不能称为没有效果。现local collector只收集task、参数、依赖和callback。以Rush为例已有19个真实task，包含buff303019/302003、RushSetting/HandleRush/NotifyRush、cooldown/delay/EndAbility/masks；`QA_AbilityHandleRush0x7cbcee0 -> native movement0x4461d50`、`RushSetting0x7cd4e90`及`NotifyRush0x7cca7b0 -> instance virtual0x3d8 ->0x7eba5d0`是后续运行目标，当前未执行。

投掷物/射出物必须由当前技能真实task参数决定类/模板、初始变换、目标和owner；服务需运行碰撞/命中/寿命、Buff应用/移除、属性和伤害/治疗、召唤物生命周期并复制真实结果。当前未闭合所有技能的对应task运行函数、对象创建字段和效果复制通道；不允许用一个“cast success”、冷却图标或静态Actor替代。`AbilityExcuteDataArray`默认RepNotify0x4c7c060在现存有界body中主要筛选/遍历/记录，未发现通用effect replay；不能把它当全部技能执行器。

技能执行状态已知通过owner `SkillState +0x620`和3P +0x648：OnRep链0x607a330->0x3411770->0x33e4490->0x340e050->0x33d9070，校对entity identity、UpdateIndexArray、enter/rollback/leave并调用DataSystem0x351f550。必须由实际权威执行记录产生Using/ExcuteID/ExcueteDatas及node参数/时间；已有ordinary layout不足以授权伪造这些值。

## 7. 可执行调查与实施顺序

1. **先冻结观察来源**：协作者试验结束和恢复后再改运行源。比对本报告hash、启动封存source_pins及新trial，不把前轮typed引用或本轮中途文件冒作当前态。07:17Z核对的8份核心运行模块曾全部与trial884项source_pins对应值相同；07:42:59Z复核时其中movement runtime已变为新SourceGuard版本，另外7份未变。原观察只证明旧封存来源；新代码需新as-of及独立验证，不能回写原试验记录。
2. **补角色FSM最小观察**：只读当前typed实例h6实际值，Identity/databoard和local tick/active child context；记录MainInit->Sub、WaitSkillUse、BasePose/Sprint动作和checking变化。若h6确实缺失且服务器语义前提已实现，以普通Net更新h6；再验正常OnEnter/事件订阅，禁止硬写内部permission。
3. **接入第一条真实技能请求**：field46独立codec已存在，30/31/38源推导grammar见第11节，尚未接入运行时authority。先按已恢复的constructor/link/serializer实现受档案profile限定的参数codec；用户自然输入一个实际选中干员的support/active，保留本局component GUID/field/raw bit slice和连续可靠前缀作独立对照。27/28未在本轮展开。重复按33与Fire4不能代替第一次激活；不以固定延时或ACK推测激活。
4. **做单局技能authority事务**：admission/entity/execution ID、context、mode选行、charging/cooldown、cancel/duplicate语义和当前服务位置都进入同一状态。恢复task触发0x34e4ca0下级virtual0x2a8实际目标，按所选技能真实task实现effect；只在实际提交后发相应RPC/SkillState/update indices/属性。先完成一个技能家族闭环，再扩展其余真实分支。
5. **补全运动权威**：先按真实包reason离线重放；逐项恢复MoveFlags与packed mode映射、base/bone/custom/vault/extensions完整线格式，以及timestamp reset/ACK/correction。加入当前局碰撞/胶囊/地面/水体状态后，让交互、AI、出口统一使用有效权威位置；对未知分支明确拒绝而不装成已执行。
6. **Sprint/体力及生命接线**：同次Shift按/放期间观察input逻辑owner、FSM事件、bWants/bSprinting、速度与Stamina连续变化，明确原生tick/扣减/恢复规则与复制布局；再实现本局tick。血条核对Widget ViewData后修真实绑定/通知，伤害/治疗加入相同权威事务。
7. **持久化边界**：本局位置/体力/冷却/执行状态随本局保存以支持明确重连规则；skill ID/template账本只保证本地实例/请求身份唯一。物品化技能扣弹药或产生可带出物品时通过同局库存事务守恒；死亡、撤离、重连不重授予/重放效果。只有结束的唯一结算提交才能改账号库存。

## 8. 原生验收操作与判据

这些是后续修复验证操作，本轮没有执行：

1. 两个不同seed分别入场；检查同局出生/朝向、胶囊落地及PC/Pawn/PS/角色身份一致。返回大厅换干员再进场，旧连接/技能实例不能参与新局。
2. 同一段平地按W走5s、Shift跑5s、放开恢复，再依次蹲/趴/跳、合法障碍翻越/攀爬、允许干员滑铲、水中上下潜；每次记录实际姿态/速度、raw movement flags/mode/extensions、服务位置与原生结果。无基座条件通过不能算移动平台分支通过。
3. 连续10分钟和1800秒上限观察，把移动拒绝按原因累计；允许真实稀疏/丢包及合法时间戳重置后恢复，客户端预测不能无限偏离服务位置。新建局/reconnect应检查代际隔离。
4. 所选干员每个实际可用slot分别短按、长按/释放、重复按、取消、耗尽、等CD恢复；救援无人机等真实初始0充能技能按对应120s行等待。同时核对输入事件、服务请求、authority判定、充能计数、任务/对象/伤害治疗或Buff及结果复制，不能只看图标。
5. 执行中死亡/中断、重复可靠请求及重连各一次，检查效果和扣除仅提交一次、取消规则和回收一致。涉及技能物品时核对库存数量守恒及最终存档。
6. 生命做一次受控伤害/治疗，数值、血条ViewData、死亡状态一致；HP100不应为UI效果更改成200。所有试验需按已授权流程1800秒收尾并核对SDK/INI恢复。

结论：这些玩法的主要缺口不是再加几个Actor或ACK。角色作者状态图进入、技能真实命令与权威执行/充能/效果事务、完整移动模式与纠正、stamina/health权威状态仍须逐条接通；本报告给出的未知值必须通过具体来源或有界原生观察解决。

## 9. 08:19 UTC 追加：field46 参数与原生分派契约

### 参数格式已闭合，运行时未接线

协作者已新增 [skill_trigger_behavior_codec.py](../work/skill_trigger_behavior_codec.py:68)，SHA256 `221e00a5fa46d82d52389819b6f01eee367d12309fbc8c6ed91bc011e5e9edbf`；其profile验证本局已存在且serial非零的弱键布局、实际 `/Script/DFMGameplay.DFMSkillComponent`、C->S reliable flags `0x220cc0`、ClassNetCache index46/max98/checksum2063178528以及原生serializer。field46是函数网络index；参数relative handles1/2和对象native offsets0/4都不是另一个RPC index。此模块是独立参数codec；当前control_connection/bootstrap/movement_runtime没有引用它，不能称已消费技能请求。

参数从字段payload的当前bit cursor连续读取：`Pbehavior:1, [behavior:6 if Pbehavior], Pskill:1, [SkillID:signed32 raw little-endian if Pskill]`。合法总长为2/8/34/40 bits。缺省参数先经原生初始化得到0；没有8字节native参数块复制、额外struct presence、按字节对齐或末尾handle。实际 `ESkillBehavior` 名值表41项为0..40，因此原生enum serializer的两条archive-version分支均需6bits；codec对41..63作明确不支持处理，不宣称原生也必然同样拒绝。int32是无byte-swap档案的4字节原始signed值，从当前bit位置读写，不是packed int。

原生依据：[实际parameter serializers](../work/evidence/skill-activation-authority-20261020-v1/native-trigger-behavior-actual-parameter-serializers.json) 的接收器 `0x12db93c0` 含初始化和逐非bool parent的presence位，`0x12db96cf`推进bit cursor、`0x12db96e1`在presence=0时跳过；enum `0x10e29fa0` 在 `0x10e2a031`调用档案virtual+0x68。int32 hook `0x10e5ce20`落到 [0x286bf70完整96B leaf](../work/evidence/skill-activation-authority-20261020-v1/native-trigger-behavior-int32-structured-leaf.json)，codeSHA `b467e80802b4d423db586946750d50f7e028e4172910cdf4721a5a875b14deda`，正常分支 `0x286bfac mov r8d,4` / `0x286bfb2 jmp [rax+0x60]`。descriptor virtual+0x90分派另有 [原生指令](../work/evidence/skill-activation-authority-20261020-v1/native-trigger-behavior-rpc-command-dispatch.json)。这些来源的完整文件hash在JSON。

本轮在内存中离线复跑252组fixture roundtrip：41种behavior与5种signed32边界/代表ID全部同时present共205组，behavior-only41组、SkillID-only5组、全部缺省1组；2/8/34/40bit四种长度均通过。这只核对codec实现和固定来源，没有发送报文或证明任务执行。

### SkillId=0 的语义与输入关系

[DFMSkill正常实现0x342bbd0](../work/evidence/skill-activation-authority-20261020-v1/native-trigger-behavior-rpc-wrapper-and-implementation.json) 在 `0x342bc46 cmp dl,0x15`筛掉SupportWeaponFire21，其余进入 `0x3316dd0`。后者在 `0x3316e47 test r8d,r8d`后：SkillID>0直接一次调用 `0x3315ec0`；SkillID<=0则按1..9循环调用 `0x32fb710`取当前SkillID，再用同behavior逐项调用 `0x3315ec0`。所以报文缺省0是有意义的fanout请求，不能按普通“无效ID”丢弃，也不能将1..9当作ID或charging/UI slot。

域依据为 [UHT GetSkillStateID声明](../work/evidence/skill-activation-authority-20261020-v1/native-gp-skill-uht-contract.json)：getter `0x60712f0`，参数 `SkillStateType` 为enum/native offset0/getter `0x607f3b0`，返回signed32/native offset4；[exec60761e0](../work/evidence/skill-activation-authority-20261020-v1/native-gp-skill-bounded-dispatch-catalog.json)直接调用 `0x32fb710`。因此循环的是SkillStateType域；本轮未恢复1..9各数值的完整枚举名映射，也没有读取按键瞬间各类型对应哪个当前SkillID。[分派278B](../work/evidence/skill-activation-authority-20261020-v1/native-trigger-behavior-fname-and-runtime-dispatch.json) codeSHA `1cf065c90d8b64eca6d1f82c0e9f73e15e2d7525cce036d43e11ec70aa9559c3`。`0x3315ec0`还有delegate、context/实例有效性及virtual回调，故解出行为并非已经接受或提交effect。

重复按的精确静态来源已复核：[command body](../work/evidence/skill-flow-research-20261020-v1/native-input-command-charging-data-bodies.json:51629) 的有界46543B span/codeSHA `867debd449bf5c9c5b449b95957bc513f400ad9c9e3abf219a41b63f26769ada`（来源明确未宣称完整native函数）。经过有效性检查、context+0x9c条件和 `0x31a3c70`返回值分支后，`0x31bc411 mov dl,0x21` / `0x31bc416 call 0x60738a0`发送RePressedInSkill33，随后 `0x31bc422/0x31bc427`以同ID/behavior调用本地 `0x3315ec0`。前述WantUse/WantUseEx command1/2和首次 `ServerActivateState30`属于另一条初始化/激活路径；不能把所有按键统一转成33，更不能把Fire4或NormalStart0当无条件首次激活。context+0x9c、`0x31a3c70`的完整字段/返回语义与实际按键时序仍待闭合。

### 保存报文支持什么

本轮仅调用 [审计函数audit()](../work/audit_skill_trigger_saved_packets.py:287)，不执行会写文件的main。重放冻结trial635个保留datagram，4条超出application profile跳过；按真实Pawn open和DFMSkill Name/Outer定义取得一个绑定。359个完整incoming Pawn body、其中标记admitted的235个均可完整解析；field46共8条，都是8bits、SkillID缺省0，Fire4六条、EndFire20两条，8/8参数逐bit roundtrip。没有RePressedInSkill33、第一次激活成功、充能或效果证据。结果JSON规范化后与协作者 [saved audit v3](../work/evidence/skill-activation-authority-20261020-v1/saved-current-skill-trigger-wire-audit-v3.json)相同；未打印或另存私有payload。

关键限制：从真实Hello序号重放，可靠连续前缀只恢复175个ready Pawn body，**其中field46为0**；channel4仅14个reliable-ready、161个unreliable，另有9个remaining queued。capped capture缺失中间包，不能补造序列；“admitted datagram”允许携带排队中的reliable body，不能据8条标记admitted就宣称已按顺序投递，更不能推定与某次人工按键的关系。8条只能证明客户端实际生成过此参数格式。C->S普通引用中的Default GUID1还需按 [原生引用分支](../work/evidence/skill-activation-authority-20261020-v1/native-skill-wire-default-guid-reader-v1.json)读取flags、路径/FString与Outer，不能只跳过一个packed GUID就把后面当field。

### 下一步具体接线

1. 先完成本局DFMSkill对象的Name/Outer/GUID绑定及连续可靠ledger投递，再对field46调用已存在codec。解码失败保留有界原因；不得用历史component GUID或admitted packet事件代替ready body。
2. authority在同一局状态中复制真实派生分派：21被DFMSkill此正常分支过滤，正ID精确定位已授予context，非正ID查询当前SkillStateType1..9映射再分派。保留来源原有delegate/context/实例判定，尚未恢复的virtual/task分支显式未实现；不要发cast成功、扣充能或生成效果。
3. 下一有界采样只需覆盖：同次自然首次按/释放/再次按的输入时间点、当前Using/ExecID与UserCommandDataMaps的Pressed记录产生/消费、各SkillStateType当前SkillID、连续可靠原始切片、30/38/31/27/28自然调用后的existing layouts。第10节已闭合+0x9c身份和0x31a3c70本地判定；拿到first activation参数后，才能把真实charging/task/effect事务与结果复制接到该已授予实体。

## 10. 09:11 UTC 历史边界：首次参数与重复按条件

本节关于30/31 flags、排序的未知已由第11节后续源码证据解决；保留当时结论，避免把后续研究写回冻结观察。

### field38 能推导参数格式，不能伪称实际布局已观察

`ServerEnterFSM` 的当前观察ClassNetCache为index38/max98/checksum1018850503，方向C->S reliable；[同版本UHT](../work/evidence/skill-activation-authority-20261020-v1/native-gp-skill-uht-contract.json) function params `0x1cd488d0` hash `b66924ed9096dfe25288adf9278b27ff0f306472beccf4b6154c56aeea58b505` 明确只有一个 `skillid`：gen3 signed32、native offset0、dimension1、参数flags `0x10000000000080`。其exec `0x607ab30`先取一个int32，再到virtual0x510；实际DFMSkill此目标仍是 `0xd5f350`空返回，收到38不能产生技能效果。

结合第9节已经核实的普通RPC接收器逐非bool parent presence与相同gen3的int32原始4字节leaf，可**源推导**普通路径下的参数grammar为 `Pskill:1,[signed32 little-endian if present]`：1或33bits，省略值0，无额外对齐/structpresence。单参数不依赖未知parent排序，也不涉及FSkillEventArgs递归或其cpp ops。可以据此写一个明确标为source-derived的离线参数codec；本轮没有新增codec或发送该格式。

证据级别必须保留：冻结v2对38仍是`not_queryable_uninitialized_weak_serial`，无existing FunctionRepLayout、parameter hook绑定或该field保存包roundtrip。故本报告不把源推导升级为observed wire profile，不补造parent/command handles或弱键。最小确认只需一个自然38请求的精确slice，或其自然初始化后的existing layout（单parent/int32 leaf应与推导相符）；不能为取得布局调用会分配serial的getter。

### field30 与31的剩余问题已缩小

`ServerActivateState30/checksum619273286`的声明是signed32 skillid native0，加SkillEventArgs native4，总native参数88B；[SkillEventArgs声明](../work/evidence/skill-activation-authority-20261020-v1/native-skill-event-args-fields.json)是84B、alignment4、13项。native bool setter已进一步给出pressed+0、cancel+1、bTryAddAmmo+0x14、GetLocAndDirSuccess+0x38；另外是ExcuteID+4、Target+8、TargetUid+0x10、AddAmmoWeapon+0x18、PlayerInput+0x20、Int32Value1+0x2c、ScanableActor+0x30、ScanableCamLoc+0x3c、ScanableCamDir+0x48。[bool原指令](../work/evidence/skill-activation-authority-20261020-v1/native-enterfsm-exec-and-event-bool-offsets.json)。这些是native地址内字段位置，不能拼成wire。

本轮还核对了普通 [RPC property布局构建器](../work/evidence/map-system-audit-20261018/native-owned-weapon-rpc-property-layout-builder-v1.json)：`0x12d9b353..367`依据被引用struct flags+0xb8的bit0x400选择native NetSerialize叶子或递归子字段。因此不能假定整个args是一项84B，也不能在13项前各加presence就完成codec。其cpp ops factory `0x607f150`确实构造vtable `0x16777e58`、size84/alignment4，但尚未把UScriptStruct实际flags的构建与子字段serializer/排序完整闭合；本轮不凭vtable存在或+0x70指向常量返回函数就推定所选分支。[ops来源](../work/evidence/skill-activation-authority-20261020-v1/native-skill-event-args-cpp-ops-vtable.json)。这部分需要实际existing parent/command展开，或等价地完整重建同版本struct flags、property links和各叶子binding；单UHT声明不足。

`ServerActivateSucess31/checksum2014345607`是S->C reliable，声明只含两个signed32：skillid native0、ExcuteID native4，exec也按此取参。普通路径**源推导**每个int32有自己的presence，因此总长只能2/34/66bits，缺省0；但exec取参顺序、native offset和UHT数组次序不单独证明网络parents顺序。本轮离线读取的 `InitFromFunction0x12db2cb0` 838B/codeSHA `109d3a2cbbcaaf4b58494c2f68628595c343d2c1a2b6c62b93b7c8754968acc6`沿运行时property link建立parent，选flags `(flags&0x480)==0x80`，不能把未复原的property link顺序伪装成已经观察。31应先取得parent顺序或完整重现构造链；只在真实authority激活成功分支后产生，不能拿它替代执行事务。

### 已证实的重复按条件

现在可以将前节两个unknown换成具体字段：GPAbilityEntityData的`UsingAbility` property record `0x165d2380` hash `d1f68dcc78b39a186c345e07fa4e8d049510d0e5c90979fd44d5a1ba320327e5`，[UHT引用](../work/evidence/model-init-chain-20261018/native-skill-entity-data-struct-declarations-v1.json)绑定setter `0x19e1730`；缓存原字节 `c6819c00000001 c3`为`[rcx+0x9c]=1; ret`。故这里是UsingAbility byte，不是generic initialized、bFSMIsInited或权限bit。

原生 `0x31a3c70`连续pdata范围75B，codeSHA `3bd63c2ddf44bd5f342c616a7fc915ae082d5f7d2d63668ca17ee55a42076caa`：取数组数据起址，读取count+8，逐byte比较`*rdx`，找到返回true，空/无命中返回false。该调用前写入局部byte1；对象由组件+0x760 `UserCommandDataMaps`按本次SkillID通过 `0x31a4990`取得，命中返回pair+8，缺失转 `0x31a4430`构造零默认value并返回。其不是额外的CanUse、CD、charging或脚本权限调用。

本轮只读原盘与缓存还闭合了value和枚举：getter `0x6087080 -> FStructParams0x1cd4b510` 为40B的`SkillUserCommandData`，recordSHA `d3aae9e033739f06605f452d6897cc3d7e0d6c1af3e63aec4d71aa3872f9df35`。`UserCommand` enum数组在+0，`ConsumeCommand`数组在+0x10，内部enum getter `0x607f530`引用 `ESkillBtnCall` record0x1cd4a568。原盘名值表0x16774f30/80B hash `c0f211c0fe086fbe3170169b930dc5eb02b1ec3ab1622e078e1d069e25f87702`，真实名值为None0、Pressed1、Released2、Click3、LongPress4。因此该helper在这里就是检查UserCommand包含Pressed。

对已固定46543B command span的直接控制流做只读reaching-definition核对：没有间接jmp；到 `0x31bc3cb` 的stack+0x60唯一到达写入是 `0x31b69cd`（前一条调用0x32f6770按SkillID取context），到 `0x31bc3e3` 的DIL唯一到达定义是 `0x31b398a xor edi,edi`。所以重复发送33的局部条件可明确为：输入命令Pressed1、context通过0x351d070有效性检查、UsingAbility非零、当前ID的UserCommand含Pressed1；随后同ID的33先发送RPC再调用本地behavior。这里只闭合这组局部分支，完整上游资格和后续效果没有因此恢复。

可交给实现者的下一步已变具体：首次输入仍走既有作者FSM/WantUse/首次激活链；运行时记录Pressed/Released到该局、该授予SkillID的UserCommandData，UsingAbility只能由真实执行状态改变。再次Pressed只有上述条件满足时走33；release/Click/LongPress不自动转33。仍须核对UserCommand/ConsumeCommand由哪个正常tick加入、消费和清空，以及重复可靠请求/重连后的保留规则，才能实现幂等事务；冻结trial没有这一map按键时间序列。本轮没有改状态、补构造ID、调用原生方法或运行游戏。

## 11. 10:05 UTC 追加：30/31 参数 grammar 从原生构造链闭合

### 构造与排序已有具体来源

新增本会话的 [离线查询脚本](../work/research_skill_contract_20261020.py)，`--verify-contract --compact`核对固定原盘SHA、缓存manifest与逐范围代码SHA，读取UHT数组并按已证明的构造规则派生schema；只输出stdout，不执行native代码、不写协作者文件。这是源码验证器，不是技能执行器或生产网络codec。

`SkillEventArgs` 的factory0x607f150构造ops vtable0x16777e58；UScriptStruct ctor0x10cf6370将ops存+c0、将声明flags1存+b8，再调用PrepareCppStructOps0x10d03cb0。后者2849B/codeSHA `0d9966373ca481bae56f9fc7c925991660ad667eaa3a0f03856b1a524baa7fc3`，关键原字节：`0x10d03fc5 ff5060`调用ops+0x60；`0x10d03fc8 84c0`；`0x10d03fca 0f8425010000`在false时跳到0x10d040f5；只有true分支经过`0x10d0405a 810b00040000`设置StructFlags0x400。Args ops+0x60真实目标为0xd5f3a0，原字节`32c0c3`返回false。故同版本标准构造链的Args明确走递归字段，已无需等自然layout来区分这个分支。

网络parent顺序也不再靠offset猜：ConstructFProperties0x10ea37f0从UHT pointerarray正向读指针并+8；FProperty ctor0x10e3e530的0x10e3e5da调用owner virtual+0x258。UFunction/UScriptStruct对应slot均为0x10cf7980，13B/codeSHA `8b1e309a8c8c68fc15228cb4f840e49537f6ee9d3438c27d7de9e8b79d6d3407`，完整字节`488b4170 48894218 48895170 c3`，即`new.Next=owner.Children; owner.Children=new`。31的原盘数组0x1675bda0/16B/hash `0abbe8bbc0259df7f63670dcb45c312e9d288ebc4b9a60e8b3f4ec42f0acdf73`顺序为ExcuteID、skillid，实际头插后成为skillid、ExcuteID；30同理成为skillid、args。随后Bind、StaticLink/InitializeDerivedMembers和InitFromFunction的这条正常链没有重排Children；InitFromFunction沿+0x70/Next+0x18建parents。Args子字段另由0x4a24e50按FProperty native offset+0x54升序排序，仅同offset时比较名称；13项offset互异。

### 精确普通参数格式

以下为no-byte-swap、小端档案的**源推导grammar**；没有声称30/31已观察到existing FunctionRepLayout或真实参数报文。`P`都是1bit，`i32`是有符号原始32bit，Vector是原始X/Y/Z各float32，均从当前bit位置连续读写：

```text
31: Pskill, [skillid:i32], Pexec, [ExcuteID:i32]       # 2/34/66 bits
38: Pskill, [skillid:i32]                            # 1/33 bits
30: Pskill, [skillid:i32], Pargs, [
      pressed:bool1, cancel:bool1, ExcuteID:i32,
      Target:NetRef(E), TargetUid:i32, bTryAddAmmo:bool1,
      AddAmmoWeapon:NetRef(E), PlayerInput:Vector96,
      Int32Value1:i32, ScanableActor:NetRef(E),
      GetLocAndDirSuccess:bool1, ScanableCamLoc:Vector96,
      ScanableCamDir:Vector96
    ]
```

方括号仅由其紧前parent presence控制；args内部没有逐字段presence、handle或padding。RPC receiver0x12db9742调用0x12dc23f0在已生成command范围内循环，0x12dc2554直接调用各property virtual+0x90，证明内部不是普通属性delta的逐handle流。两parent都present、三引用null时30恰为446bits；args present部分的最小长度为412bits，不能用88B内存长度代替。

叶子已逐项接到实际类型：gen3 ctor case0x10ea3a58产生FIntProperty vtable0x15a863c0，NetSerialize0x10e5ce20→0x286bf70四字节；Bool ctor case0x10ea41aa产生vtable0x15a868a0，+0x90为0x10e8ebe0（106B，codeSHA `de22cc24de8a11838462d7977b4b8b8f0ce41d601e8b4902ca113fb06fe5e009`），0x10e8ebfa将bitcount置1、0x10e8ec19调用档案virtual+0x68。三个Vector使用[已经闭合的plain Vector契约](../work/evidence/model-init-chain-20261018/native-map-plain-vector-value-contract-v1.json)，含deferred CppOps+0x60=true、+0x70→0x13c0600→0x13b4a70，连续3个原始float32，非packed/quantized vector。

三个对象字段gen0xe的ctor case0x10ea4401产生vtable0x1ab610f0；+0x90为0x10e8ed20（193B/codeSHA `d9eaa90e1b5f244ffcd5913f4a2b2d829f1db277bd7e7c73b946f2cf178ec666`）。该函数从weak property取实际UObject，经PackageMap virtual+0x260序列化引用后回填weak property；wire不传ObjectIndex/serial、本机地址或裸weak内存。

`NetRef(E)`的具体grammar为：packed uint32 GUID；GUID0立即结束；非零且(GUID1或PackageMap export_mode=E为true)时跟8bit flags；flags&1时继续递归Outer引用、FString、且flags&4时跟原始u32 checksum。[完整原生读取器](../work/evidence/skill-activation-authority-20261020-v1/native-skill-wire-default-guid-reader-v1.json)0x12bbb3c0包含这些实际字节读取分支；FString为signed32计数后原始ANSI字节/负计数UTF16LE单位，保持已有档案约定。普通nonexport模式的非1已登记GUID只有packed GUID，无flags/name。E必须是已资格化的PackageMap档案上下文；不能凭某个数值或传输ACK猜它，不能以解析引用冒充创建/加载/授权对象。当地有界长度、递归限制及未知flags拒绝应明确标为本地策略，不能改称原生规则。

### 省略值与剩余边界

外层RPC参数buffer确实先清零：0x128932e9从UFunction+0xba取参数尺寸，0x1289336a置EDX0、0x1289336c传size、0x1289336f传同一R14 buffer，0x12893372调用memset0x1497fcc2；0x128933ad把同一R14交给0x128933b7→ReceiveRPC0x12db93c0。256B窗口0x12893300 hash `f2d9e3f21d7321e46826373b6900164a5010199b36988e857666cf88901aa7de`。IntProperty带CPFZeroConstructor；enum还在Link0x10e272c0的0x10e27301/30b补ZeroConstructor位，parent flag0x40因此跳过重复初始化、保持外层零值。故31/38省略int32=0以及46省略enum=0现有完整来源，而不是只据UHT假设。

Args区别已闭合：ops+0x10/+0x98=false，Prepare不设StructFlags0x8000；ops+0x120返回0x1000000000，无CPFZeroConstructor。FStructProperty Link0x10e8e960只有structflags0x8000才加CPF bit9，故Args parent会进入正常InitializeValue。0x10e8cfc0→UScriptStruct+0x298的0x10d01af0→ops+0x18的0x60804a0，构造后Int32Value1+0x2c=-1；不能把省略Args替成全零结构。10:05时默认Vector所读虚拟区0x1e2f8090/8098没有file-backed字节，故当时保留数值unknown；第12节进一步依据原盘PE零填充语义闭合为正零，仍不冒充当前运行值读取。

到这里，30/31的标准参数排列、结构分支和各wire叶子已足够开始实现受profile限定的离线codec，38单参数也已源闭合；余下不是“先找这几个函数名”。结合第12节，Args省略默认值已有等价来源；具体仍须由当前连接提供真实PackageMap profile与引用资格，做自然首次调用参数slice的独立对照，再接实际owner/entity/ExecID/charging/task/effect事务及结果复制。未实现的runtime消费者、效果和原生技能验收仍保持未完成，本轮没有发起任何调用。

最终只读复核：10:09:47 UTC时JSON内100个peer来源hash全部匹配，49个Markdown引用目标存在；源验证器38个代码范围通过。SourceGuard后来版本仅记录元数据漂移，未由mtime推断编辑顺序或trial状态；旧movement观察仍限定于对应历史hash。

## 12. 10:24 UTC 追加：Args 省略时的默认向量数值

构造函数0x60804a0的0x60804e5/4f8从0x1e2f8090读8B、0x1e2f8098读4B，写PlayerInput+0x20/+0x28；0x6080511/51e写ScanableCamLoc+0x3c/+0x44；0x6080527/534写ScanableCamDir+0x48/+0x50。三项均是同一12B常量的拷贝。此前“没有file-backed字节”不等于“无法派生源默认值”：PE加载器对该虚拟尾部提供零填充。

原盘section header文件offset0x458，40B完整hex为`2e73746400000000a020bd0100e09f1c0040130100ce9f1c000000000000000000000000400000c0`，SHA `ed2877ebeeb8311a5300fc409c1534a1327705ddff08d4ebf968eb68a22ba660`。它描述`.std`：RVA0x1c9fe000、SizeOfRawData18038784、VirtualSize29171872；虚拟零填充区为[0x1db32000,0x1e5d00a0)。所读[0x1e2f8090,0x1e2f809c)完全位于此区，派生12B全00，SHA `15ec7bf0b50732b49f8228e07d24365338f9e3ab994b00af08e5a3bffe55fd8b`。因此三个源默认向量均为float32 **(+0.0,+0.0,+0.0)**，每轴原始bits0x00000000；这不是从不存在的原盘字节中读出的数值。

完整源默认表现在可供实现：pressed/cancel/bTryAddAmmo/GetLocAndDirSuccess=false；ExcuteID=0、TargetUid=0、Int32Value1=-1；Target/AddAmmoWeapon/ScanableActor=null；PlayerInput/ScanableCamLoc/ScanableCamDir均为上述正零向量。null引用的构造助手0x109929f0，59B/codeSHA `d04267aa1f3ccc071a45286c3132905f46d42aafcd5182a7762ad45f02a80cf1`：rdx为0时跳0x10992a18，分别写weak index=-1、serial=0；这两个本机内存字段仍不是wire GUID。

固定manifest下349562443B缓存代码、无缺段的有限direct MOV-store模式检查没有发现覆盖这12B的候选；另有1737个LEA候选，未追成完整别名写入证明。故这里闭合的是正常PE初始常量语义下的**源码默认值等价实现**，没有声称排除所有运行时别名写入或读取当前全局值。离线验证器现核对39个代码范围，并校验该section header与零填充范围，直接输出完整默认表；未新增生产codec或runtime消费者。余下PackageMap资格、自然wire独立对照及真实技能执行链的边界不变。

10:25:59 UTC收尾复核：101个来源hash匹配、49个引用目标存在，JSON可解析；本轮仅更新本报告、JSON和既有离线查询脚本。
