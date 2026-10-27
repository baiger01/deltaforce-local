# 普通 F 交互、搜索与取物的原版静态证据

日期：2026-10-21。范围为普通 F 的开始、长按、释放、中断、箱子搜索和物品转移；不修改生产实现。只读取本地文件、既存原生代码缓存及原版 PAK，不读取进程、启动游戏、发送网络包或打开数据库。

## 结论与边界

这次补出了原版按物品计算搜索时间、定时完成、取消搜索，以及独立的真实 GID 取物、格子容量和计数写入片段。它们不是一次“箱子引用已收到”能够代替的状态变更。

当前 `portable_durable_world_runtime.py:240-243` 在提供 manifests 时确实返回 `RuntimeInstallation(True, ...)`；安装的是 `RegisteredBoxReceiptRuntime`。该类在 283-285 行明确 `mutation_ready=False`，拒绝原因仍是源证据合格的箱子世界位置和交互许可提供器缺失。应修正旧报告笼统的“运行时未安装”为“可安装实际静态箱子的引用收据路由，尚未具备普通 F 游戏逻辑变更许可”。无 manifests 的另一分支在 271 行仍返回 False。

后续[输入分发补查](GAMEPLAY_F_DISPATCH_RESEARCH_20261021.md)已恢复InputManager注册Interact、动作入队、分发表、实际DFHD接收者及面板反射处理的静态链；[目标接收者补查](GAMEPLAY_F_RECEIVER_RESEARCH_20261021.md)已限定面板缓存的目标组件基类，并查到独立的组件版RPC字段70及当前decoder仅接受71/72的缺口。仍不能宣称完整F可运行：当前对象生命周期/模式是否选择该路径、具体子类override、字段70网络布局、若干Blueprint条件，以及最终原版复制提交尚有未闭合边。本文用明确函数、指令和原版资产证据描述已闭合片段，不把附近字符串或候选调用算作执行证明。

## 可重放证据

- 主证据：`work/evidence/gameplay-f-interaction-research-20261021.json`。每个 query 保留原始指令字节、RVA、pdata/unwind 片段、范围 SHA256、完整线性解码，以及资产属性偏移和当前源码快照。
- 原版 EXE SHA256：`4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`。
- 只读代码缓存：peer `work/native-code-cache/1792259162856698600`；manifest SHA256：`dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。这是既有的非原子快照，不是本次实时执行证明。
- 本次重放检查了 94 个不同原生范围、330 条 unwind 记录、13 个 EXE 不可变记录/节、9 份当前源码快照；重新从原版 257 个 PAK 的索引定位并解码 8 个选定包，比较所有导出属性和继承路径；验证 15 条直接调用边和 4 条扣减分支/写入边界。

在本 checkout 执行：

```bash
PYTHONDONTWRITEBYTECODE=1 /c/Users/BaiGe/.conda/envs/python12_conda3/python -B work/research_f_interaction_20261021.py --verify
```

结果为 PASS。它读取文件并核对证据，不运行原生处理器、服务端协议或游戏。`complete_native_function_claimed=False` 保留；线性解码覆盖的是记录的明确范围，并不保证所有动态分支语义完整。

## 1. 按下、长按与释放

原版 `../../../DeltaForce/Config/DefaultInput.ini` 的 `Interact` 映射到 F。源包为 `pak-0-0-pakchunk1-WindowsClient.pak`，物理偏移 3377152，解码长度 33351，SHA256 `a8df6503e92d7b9062162ebc760f2fb792b697f02bbd1374e32cd43c7c296b87`。原版索引、压缩载荷和选择的行在 `work/evidence/f-interaction-input-ini-20261021.json`。

实际 `AGPPlayerController::OnInputInteract1` 为 `0x4e11180`，215 字节，SHA256 `71d35a6d2f32991e568812cadbe98bf9335682636ea10c32387814511c101cec`；类名和绑定记录都已匹配。勘误：`GetBaseHUD 0x517bd10` 仅作非空检查，随后仍传controller给`0x32e4000`取得GPGameplayDelegates；实际在`0x4e11206`取该对象`+0x648`，于`0x4e1120d -> 0xd96400`广播整数1。旧文将owner称为HUD、将类型转换helper称作广播均有误。该旧GP委托到具体面板的连接仍未闭合；另一路已闭合的InputManager/DFMGameplayDelegates路径详见补查，不能将两个owner或字段偏移直接拼接。旧原始证据保留不覆盖。

面板的准确名字交叉引用和 pdata 范围已恢复：

- `UDFHDInteractorPanel::DoInteract1KeyPressed`：`0x8789110`，3684 字节，SHA256 `1e15281a694e62220d48e19107df2653ed9cd44e59ab43b028830574f0a6a77e`。有有效当前上下文且持续时间 `+0x5b8 > 0` 时，保存进行中标记 `+0x8e0` 和进度 `+0x8e4`；依长按模式走不同接口回调。
- `TickLongPress`：`0x87f93d0`，2230 字节，SHA256 `c2dfceefccbd7a737e65a803cd96b2d6eeff8982b424b9b801000ecb11d423b7`。累加 delta 到 `+0x8e4`，除以持续时间并钳制进度，达到阈值后清除进行中标记并执行缓存的目标/tag。
- `DoInteract1KeyReleased`：`0x8789f80`，1150 字节，SHA256 `bcbcbb46b0bc6d1427d359ab3b7c1be330a838f936b5b2fd50f4e7863499de6d`。模式 2 走带 false 的释放接口并调用清理函数 `0x8785870`；另有短按路径 `0x878a400`。
- 短按范围确有门状态拒绝分支和 `door is not allow open or close now` 日志。它在 `0x878b081` 调用缓存对象 `[panel+0x518]` 的虚槽 `+0x490`；后续已按反射和写入路径限定为目标侧DFInteractableComponentBase或子类，不能直接命名为角色侧SOLInteractor。具体fallback和字段70路径见目标接收者补查。

对应 query：`actual-pc-input`、`panel-input-functions`、`input-candidate-identity`。不同类使用相同热补丁 ID 的探索候选已排除，尤其 `pc-f-input` 中的 ADFMCharacter/技能候选不作为 F 输入绑定证据。

## 2. 客户端目标与服务端交互入口

真实 `UDFMInteractorComponentBase::ExecuteInteractByTag` 为 `0xbb4e140`，5049 字节，SHA256 `0599382600d8f4a9d5b890543fcf055f76e4f010725a1812b6c85f0f6d681b3a`。不可变 SOL 虚表记录 `0x1a680290` 确认它处在构造器虚表 `0x1a67fe40` 的 **+0x450**，不是前述面板的 +0x490。

这段描述的是Actor版路径。后续已恢复目标组件基类fallback查角色组件`+0x458`，走`ExecuteInteractableCompByTag`和另一个字段70；不能用下述71/72的接收和codec覆盖该组件版路径。

它在 `0xbb4ee33` 调用 `ClientCheckCurrentInteracting 0xbb0e4a0`；false 会拒绝。目标接口有效等后续判断通过后，在 `0xbb4f465` 调用 self 虚槽 +0x8c0。SOL 对应槽 `0x1005f4b0` 调用 `0xffc86a0` 和 `0xceba7c0`；后者建立 actor/tag/context 参数并经 `ProcessEvent +0x220` 发送反射事件。这个客户端检查不构成服务器交互许可。

沿用已限定的网络元数据入口：SOL 71 `ServerExecuteInteractByTag` 的 Actor、GameplayTag、52 字节 `InteractingContext`；72 `ServerInteractAction` 的 Actor/tag。原生结构布局不是网络上整块 memcpy。上下文中的客户端坐标只是一项输入，不能替代服务器接受的移动位置。当前 codec 的 field 71/72 解码还要求当前引用、导出 ACK 和非 fast tag 模式；这些只能证明可解析和已送达。

此前限定的 71 `exec 0xcec12e0 -> +0x760 -> 0xbbe60e0`、72 `exec 0xcec1560 -> +0x798 -> 0xbbe8c70`，以及 `DSCheckCurrentInteracting 0xbb2b7d0 -> +0x8c8 -> 0xbbdfd10` 继续作为服务端入口。其 authority、距离、过滤、overlap、物品保护和门检查不得省略。本次新恢复的 `ServerDoExecuteInteractByTag 0xbbdfd10` 范围在 `0xbbe0c52` 查询 executor `0xbefcea0`，有效 executor 调用 `0xcf603b0`，另一分支在 `0xbbe0f5c` 调用目标接口 +0x148。

对应 query：`sol-execute-slots`、`sol-normal-execute`、`client-tag-execute`、`tag-server-dispatch`；当前 codec/元数据完整字节快照见 `final-current-source`。

## 3. 一个原版箱子及其操作进程

代表对象为原版 `BP_Interactor_Container_SafeBox`，不是新造的默认箱子。8 个源包重新解码结果见 `original-safebox-process`：

- `.uasset` SHA256 `8da4241c723f9648d0c25d6897c161ee5a845404d962877c347f53ca4d8743b6`；`.uexp` SHA256 `ed3b2ebb63ae68e6ef36e53872fb6fdffd049448c827db16080467d959688f60`。
- CDO export 8：`BoxID=920` @uexp 4058，`BoxLevel=1` @4087，`CapacityLength=4` @4150，`CapacityWidth=4` @4184，`BaseItemSearchTime=3` @4815，`InventoryIdName=99010000021` @4885。这是源默认值，不能替代实例世界状态。
- 继承路径：SafeBox -> `BP_Interact_AnimSwitcherContainer` -> `BP_Interactor_ContainerBoxBase` -> `BP_InteractorContainer_BoxBase` -> `BP_InventoryPickupOpenBoxBase` -> 原生 `InventoryPickup_OpenBox`。
- 源 tag 同时包含 `Interactor.CheckCollision.SafeBox.ReleaseLock` 和 `Interactor.CheckCollision.ContainerBox.Open` @5032。空密码默认值不等于运行时解锁，密码生成组件和实际锁状态仍需处理。
- 父资产 OpenProcess export 19 的 TriggerTags 为 ContainerBox.Open @5135，ForbidTags 为 DelayStartInteraction @5196；CloseProcess 有独立 Close tag、Switcher.Open acquire 和 DelayStartInteraction forbid。SafeBox 有自己的 OpenProcess/CloseProcess 条件引用。
- `BP_ProcessPawnOpenContainer` 的原生父类为 `InteractorProcessPawnAnimComponent`；源上半身 FPP/TPP、`ToggleDrawer` 动作、Open tag @244，以及 MustConditions @289 指向 `BP_ExecuteOpenContainerCondition_C_0`。该条件实现 `IsAllowExecute`；Blueprint 函数体未完整恢复，不能默认为 true。

原生 `AInventoryPickup_OpenBox::ExecuteInteractor 0xc1b8150` 调用继承的 `AInteractorBase::ExecuteInteractor 0xbe6ecf0`。`UInteractorOperatorProcessComponent::ProcessOperatorTag 0xbaaed90` 有实际 world/CanInteract 检查，拒绝时日志为 can't interact，之后才进入处理分支；`ProcessOperator_Implementation 0xbab08d0` 遍历组件并调用 `0xcf93850 ServerStartInteraction`。后者是 Blueprint native event，此处不能仅凭 Server 前缀称其为网络 RPC。

`OnInteractKeyReleased 0xba96fe0` 有准备中断日志、虚调用及 `0xba7a6e0`；`AnimPlayComplete 0xba641f0` 和 `ProcessPawnEnd 0xbab0c60` 有独立完成/结束路径。所有输入释放、受击、死亡到这些组件的完整绑定尚未闭合。

开箱自身也有 begin/finish：`OpenThisBox 0xc1e2890 -> HandleInteractiveOpenBegin 0xc1c8d70 -> HandleInteractiveOpenFinish 0xc1c9040`；Begin 含 actor role==3 的权威判断，Finish 有成功布尔参数、状态和事件分支。`ADFMPlayerController::ServerOpenPickupBox_Implementation 0xb58f9c0` 是另一个 PC226 箱子引用入口。看到该请求不代表 F 操作、解锁或搜索已经成功。

对应 query：`box-interactor-begin-finish`、`process-native-body`、`process-impl-hook`、`commonmove-quantity-xrefs`。

## 4. 搜索开始、计时、取消和完成

箱子开盖与物品搜索是不同阶段。已验证的原生片段为：

```text
StartLootSearchProcess 0xc1f6750
  -> 搜索状态/预处理 -> TryStartNextSearch 0xc202680
  -> FetchNextItem2Search 0xc1b85b0 -> 实际 registry/item
  -> StartLootSearchTimer 0xc1f6d80
  -> GetItemSearchTime 0xc1c0000 -> SetTimer 0x13060960
timer delegate +0x50 = 0xc1b80d0
  -> weak object 有效检查 -> OnItemSearchDone 0xc1dad90 (success=1)
  -> MarkItemSearchDone 0xc1d6110 -> TryStartNextSearch
  -> 无下一项时 StopLootSearchProcess 0xc1f9b20
```

`StartLootSearchTimer` 检查 character、loot source、实际 item 和 world；调用 `GetGID 0xc039670`，记录搜索玩家；保留实际 item、弱 character 和 subsystem 的 timer delegate，并清理旧 timer 后设置非循环 timer。在 `0xc1f711d` 获取具体时长，在 `0xc1f8a67` 调用 SetTimer。delegate 不可变虚表 `0x17ccf590` 的 +0x50 指向上述回调。

时长函数有 `BaseSearchTime_Weapon/Adapter/Armor/Container/Medkit/Key/Collection/Box/Other`，`SearchQualityMultiplier_Lv%d` 和角色修正来源，再经过数值钳制。SafeBox 的 BaseItemSearchTime=3 不是所有物品统一三秒的证据；完整最终公式/各配置值仍需逐项限定。

完成函数先从实际 item 取 GID；只有与当前搜索项匹配时清除当前项并继续。`MarkItemSearchDone` 还遍历嵌套内容/空间并通知搜索状态变化。它标记可搜索/已搜索状态，不把物品移进玩家库存。

取消片段：`StopLootSearchProcess 0xc1f9b20 -> StopLootSearchTimer 0xc1fa020`；后者走 CancelSearchItem/Currency 分支、用 success=0 调用 MarkItemSearchDone 并清理 timer。停止过程还退出角色搜索状态。本文没有把所有按键释放或死亡都假定为已绑定到这个取消入口。

关键范围 SHA256：timer `5bbf613f5c890b18483c0ae3d50ec1689a407b387a5832e7d158bf09f0c24836`；时长 `09fca44e22c57b69924aa7cc28d2e5f96816c7b867ee28ed60983ee3d2e74310`；完成 `684964926c3a7cf4ef9cb285ecef21d6248ededd890e62aad57ec8175d922456`；停止 `0c7c0d5e5da78a6936b52c9d9ee769ec7e24b18cb6602cf2df9d1c89b4df3234`。对应 query：`search-stages`、`search-timer-body`、`timer-callback-vtable`、`timer-callback`、`item-search-native-details`。

## 5. 实际取物、容量与数量

实际取物走 InventoryManager field 45 `ServerProcessItemMoveCmd`，其 owner 的 exclusive maximum=53。参数为 328 字节原生 MoveCmd 加 EnableClientTips；源布局包含 CmdGid +0、SourceGid +8、SourcePos +32、目标坐标 +40/+44、MoveNum +52、SourceLootObj +64、CmdOwner +168、SourceSpace +232、TargetSpace +240。网络解码仍须按各属性序列化，不能照搬原生布局。

`0xbfc43f0` 从组件取得实际 command owner，调用前置检查 `0xbf9e020`；通过后获取 LootingSubSystem 并调用虚槽 +0x270。EXE 中 `0x17cd2310` 确有指向 `ProcessItemMoveCmd 0xc24e210` 的不可变指针，与候选表 `0x17cd20a0 +0x270` 相符；该表构造器写入尚未闭合，保留该虚接收者类限定依赖。

已解码的真实处理范围有：`ProcessItemMoveCmd 0xc24e210 -> PreProcessItemMove 0xc24c480`、`ValidateMoveCmd 0xc265cb0`、中间处理 `0xc24f1d0`、`PostProcessItemMove 0xc2494a0`。前处理有比赛结束拒绝并在相应拾取分支从实际源实例取得 GID；验证使用实际物品、loot source、目标和位置检查，不是只信任请求的 SourceGid。返回 `0xcfb5200` 携带 CmdGid 和结果，EnableClientTips 还可让失败请求产生响应，所以“收到回复”不是成功。

`ULootUtil::CommonMoveItems 0xc113210` 按实际源/目标 GID 组计划及位置，`0xc11408c` 调用 `UItemSpace::RemoveItem 0xc1e5070`，`0xc1146ac` 调用 `AddItem 0xc19cf50`。有备份/恢复辅助 `AddItemsAndSort 0xc1a04e0`，但尚未证明所有分支事务原子性。

容量的真实叶子是格子和类型检查：`CanAddItem 0xc1a89f0 -> CheckItemFitSlot 0xc1abfe0`，并检查 `CheckLocationEmpty 0xc1ac570` 的旋转尺寸、边界与占用。`AddItem 0xc19cf50` 在 `0xc19d0fe` 再调用 CheckLocationEmpty，成功后才在 `0xc19d13f` 调用 AddItemInternal。它与单个堆叠的 MaxCount 是不同限制。不能用 SafeBox 的 4x4 默认值给所有实例通过容量检查。

实际计数字段已限定在 `FInventoryItemInfo`：GetGID `0xc039670` 读 +0x28，GetCount `0xc038870` 读 +0x38；SetCount `0xc0cdb50` 会处理有效性/最大值，改变时写 +0x38 并以字段码 2 调用 `0xc05e300`。ConsumeCount `0xc028950` 的非热补丁分支严格如下：

```text
0xc0289bb test edx,edx        ; 零请求跳过
0xc0289cb cmp edx,edi         ; edi = 当前 +0x38
0xc0289cd ja 0xc028ac8        ; 无符号 requested > current 跳过写入
0xc0289d5 sub eax,edx         ; eax = current - requested
0xc0289d7 mov [rbx+0x38],eax
0xc0289da cmp edi,eax         ; 比较的是写入前/后数量
0xc028aba call 0xc05e300      ; 状态通知，dl=2
```

因此请求恰好等于当前数量会写零。这里没有独立 signed-negative 过滤，本文只主张上述无符号比较语义，不主张返回值契约。GainCount `0xc032b10` 则在相应路径加数量、按 +0x3c 钳制并保存溢出量。ConsumeCount SHA256 为 `ecda3e986fe6f9ef419d7f03155a78a089d9a553a8180adb7bfe8e98f9dfad9c`。

这些是已验证的扣减/增加叶子。特定部分堆叠转移到这些叶子的完整调用路径、全部回滚条件、最终 FastArray dirty/OnRep/客户端库存更新仍未闭合，不能宣称“原版部分取物已可执行”。大量 `[object+8]/[object+0xc]` 的减一是共享引用计数，不是物品数量扣减。

对应 query：`looting-process-core`、`move-main-dispatch`、`looting-process-virtual`、`looting-vtable`、`real-space-remove-add-capacity`、`real-count-leaves`、`commonmove-quantity-xrefs`。

## 6. 当前实现差距

当前 `portable_world_loot_dispatch.py:132-157` 只实现源限定的本地 immediate-open 策略：解码后还须真实服务端许可回调返回 True，tag 必须为 ContainerBox.Open。它不实现上述原版动画/条件进程和逐物品搜索 timer。`open_field:111-127` 也要求实际锁/许可提供器。

其 `move_request:163-194` 只接受 SourcePos=302、显式空格、原始整实例数量、规定的引用/标志约束，通过有限权威的 move_whole 再投影；不含原版任意拆堆、自动安放、交换、装备、钥匙、所有错误码或完整成功事件。这是有界本地策略，不是完整原版取物行为。

下一步的精确依赖为：实际当前世界/位置及锁权限提供器；物理输入委托到具体面板和接收者类；操作组件 Blueprint 条件及中断绑定；box finish 到搜索启动的真实调度；MoveCmd +0x270 接收者构造绑定、部分堆叠数量路径及复制提交。引用发现、导出 ACK、PC226 收据均不解决这些依赖。
