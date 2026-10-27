# 本地战斗链重新调研（2026-10-20）

本报告是只读接入审计，不是玩法修复完成记录。协作者根目录为 `historical map checkout`，下文相对路径均以该目录为根。输出只写本项目这份报告及配套 `work/evidence/gameplay-combat-research-20261020.json`。没有启动客户端、打开进程、调用游戏方法、发送报文、改动协作者运行/诊断源码或生产数据。

版本边界：既有原生资料绑定客户端 SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`，可执行缓存清单 SHA256 `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。本次重新读取当前源码、保存的试验资料和七个当前安装 Lua 块；未重新采样可执行区。精确文件哈希、函数和 RPC 索引保存在配套 JSON，不包含运行时地址、密钥或凭证。

## 结论与已纠正的旧说法

1. 武器入局已经超出“只有库存占位图”。当前真实快照、两枪完整配方、Owner、身份、装备位置、manager 绑定和初始 timeline 已接线；最新保存观察中两枪均完成内部初始化，第二枪激活，均有真实 1P mesh。它们仍隐藏且无挂接父对象，因此第一人称持枪未通过。
2. 旧 `ai-runtime-research-20261020-weapon-branch-v1.md` 中“owner runtime 没有 production caller”是早先状态。当前 `legacy_ds_control_connection.py` 已调用 owner switch adapter，并具备响应排队、发送、重传和正 ACK 提交。不能重复列为未接入。
3. 试验 `1792478435036855300` 保存的 `game-server-packets/report.json` 中 `owner_switch_requests_accepted=0`、`owner_switch_result_delivery_acks=0`。它没有同时证明物理切枪输入、对应完整 owner 请求、handler disposition 和回包消费，故既不能判定 handler 有 bug，也不能判定切枪成功。
4. 开火、弹道、伤害、防具磨损、医疗、死亡和 AI 决策尚没有可证明的完整本地权威链。真实客户端类型、接收布局或静态资产存在，只证明有可恢复的协议/显示入口。
5. 必须分别完成两项工作：恢复原客户端协议及生命周期；实现明确的本地服务器战斗规则。没有官方 DS 行为证据的命中、伤害、感知或 AI 决策不能冠以“原版算法”。

## 武器入局与第一人称显示

来源到实例的链为：大厅真实携带物品 → `native_match_loadout.snapshot`（`outputs/df-local-server/dfserver/native_match_loadout.py:26`）→ admission 不可变快照 → `portable_carried_weapon_selection.select`（`work/portable_carried_weapon_selection.py:55`）→ `portable_modular_weapon_initialization.initialize`（`:142`）→ recipe（`work/portable_modular_weapon_recipe.py:58`）→ equipment position → manager 三表/WeaponInfo/Active → owning timeline。

必须保持 `inventory GID / template RecID / ServerWeaponIdentity / Actor NetGUID / native WeaponSlot / business equip position` 六种身份的区别。位置 111/112 来自真实携带槽，不能用背包格坐标代替。当前本地初选规则优先 MainWeaponLeft 再 MainWeaponRight，是明确本地策略；不能称为已恢复官方 GetDefaultWeapon 评分。所有实际枪、配件和弹药仍须来自同一 admission，不能在客户端缺模型时新赠一把枪。

原生正常链的已保存代码位置：

- `OnRepCharacterOwner` exec `0x601e530` → `0x58da750`；WeaponId notify → `0x58dae30`；配方 notify → `0x58d9700`。
- post-notify `0x58e0ca0` → readiness `0x590ce90` → 初始化 `0x58c61f0`，检查 World、正 WeaponID、CharacterOwner、非空节点，刷新组件 `0x58e5120`，并重放待激活状态。后续属性可以经正常 notify 完成初始化；不能假定必须全部在第一 open 包内。
- appearance 正常刷新 `0x21d9a00` → mesh loaders `0x21c0b70/0x21c07a0` → 同步或异步加载回调 → `OnWeaponMeshLoaded 0x21cc280` → `RefreshWeaponAttachInternal 0x21d34c0`。角色 mesh 完成 `0x21c4410`、相机模式变化 `0x21c4020`、装备可见性变化 `0x21c4210` 另有真实刷新回调。
- 挂接依赖实际 GPWeaponProxy、DCAppearance 接口、当前角色 mesh、武器状态、socket 及占用状态。`CustomAttachToComponent` 的 DCAppearance-null 分支会跳过；部分正常状态会 detach。`b_IK_Gun` 字符串存在不等于它是当前正确 socket。

最新保存观察（非原子，不能跨时点拼成一致状态）：

- `owned-weapon-mesh-followup.json`，`2026-10-20T06:46:28Z`：manager 中两个 Modular 的 internal initialized=true；第一个 activated=false，第二个 true；两者 WeaponMode=1（真实 enum 为 OwnerFirstPerson），Actor.bHidden=true；mesh.bVisible=true、bHiddenInGame=true、AttachParent=null，且有真实 RuntimeSkeletalMesh。
- `owned-weapon-current-metadata.json`，`06:51:12Z`：当前 manager CurrentActiveWeapon 和 Pawn.CacheCurWeapon 指向第二把真实 Modular；timeline 仍是初始 ring。
- 两枪 `WeaponAppearanceScope` 均因 `Invalid current metadata object address` 拒绝，nested owner-current 读取也拒绝。这不等于 appearance component 为 null，也没有证明 HideReason、HiddenMap 或某 socket 错误。

下一步有判别力的恢复是修正只读资格后，在同一实例/接近时点记录真实 proxy/data/function 接口、FuncAppearance.HideReason、DCAppearance.HiddenMap、bAttachWeaponToCharacter、detach-on-hidden、当前角色 mesh/socket 选择、mesh/camera 回调缓存及最终 AttachParent。只修满足来源的缺失通知/绑定/普通复制，不直接写内部 initialized、activated、hidden、socket 或缓存字节。

## 切枪输入与服务器结果

正常拥有者链：物理输入/当前绑定 → Native `SwitchToTargetWeaponInner 0x5651590` 的 CanSwitch/Blackboard/ability/frozen/swimming/pending 条件 → `AddSwitchFrame 0x55e7ce0` → local timeline `0x587e4a0` → `0x58d0b20` → authority-test `0x561f840` → 非 Authority `0x5646760` → ProcessEvent `0x6143fc0` → `RPC_ServerVerifyFrame` exec `0x6146e40` → `0x563ed10`。

真实 receiver 为 Pawn 下稳定 `WeaponManager` subobject，ClassNetCache exclusive maximum=17，VerifyFrame index=10，ClientNotifyFrameInValid index=9。参数是 ClientFrame 和 InCheckCode；native params 64 bytes 不是线上原样 64 字节。现 codec 的两个父 presence、204 frame leaf bits 和 64 check-code bits 有来源。操作 Start=0 → ActivatePending=1，即使 Instant SwitchType=2 也不能跳过；Cancel=2 的目标是 current 并清 pending。真实远端结果走 manager 普通 handles 9–12 的 TimeLineRepData，`OnRep_RemoteTimeLineData 0x5631dc0` → ring import `0x58ef280`（交换 Local/RemoteFrameNo）→ `ApplyCurrentFrame 0x55ec380`。RuntimeContext 是消费者内部状态，不是直接复制目标。

当前接入点：

- `work/portable_owner_switch_profile.py:29` 对同一快照完整初始化图、recipe/位置、初始 timeline 和 source generation 生成 profile；`:81` 调 `receive_admitted`（下列 SourceGuard 复核后的当前行号；初次读取为28/80）。
- `work/portable_weapon_switch_runtime.py:268` 只消费真实可靠 assembler 释放的完整 body；`:299` 支持同 body 的多个合格请求，`:311` 依次执行本地状态策略。
- `work/weapon_switch_owner_operations.py:91` 校验本局身份、frame 顺序和 Start/Activate/Cancel；保留 check code，不声称官方反作弊校验等价。
- `outputs/df-local-server/dfserver/legacy_ds_control_connection.py:1987` 调 `legacy_ds_owner_switch.consume`；后者 `:72`、`:117`、`:160` 分别做决策、排队投递和真实回执提交。当前 profile 从 `game_server_probe.py:491/1287` 注册；不能遗漏这些 production caller。

本局必须持有 semantic current/pending、client/server frame、去重摘要、transport generation 和确切响应 bytes；可靠 ACK 只提交交付 cursor。存档保存最终装备/消耗，不需要把一次切枪动作当账户事务。验收须记录“实际输入时间 → 合格 VerifyFrame → disposition → server frame → 返回 timeline → current/pending 收敛 → 两把正确可见枪”，包括取消、快速切换、重传、重进局。

来源漂移复核（2026-10-20 07:49:14 UTC）：初次读取的 `work/portable_owner_switch_profile.py` SHA256 为 `70550f5ba2d33035c0c7da9e013e9e2bad7ab7b0cadef9e4c695e704e2f409e5`，现为 `4c731de865c218349520246af74ac042c1cef03d3780fc4f6bb7add7a18cc0d4`。与初次完整读取内容比较，变化为新增 SourceGuard import、将 `work/portable_source_guard.py` 纳入 source_pins、以 `SourceGuard(ROOT, dict(pins))` 替换原逐次重新计算所有文件哈希的 current 闭包；武器选择、初始化图/位置/recipe 校验、timeline seed 和 consume 调用体未变化。当前 SourceGuard 文件 SHA256 为 `4a8cbc45919a8da92568ae2783326826170a12a5a2e718a0d7bee445985fee12`；代码在建立 lease 时校验完整 hash，Windows 使用只允许共享读取的文件句柄并在回调检查身份/指纹，非 Windows 回调继续重验 hash。这是来源资格实现变化，没有新增持枪/切枪原生验收。JSON 的当前 pin 更新为新值，`source_pin_rechecks` 保留旧 as-of 值及本次原因；本次仍未修改 peer 文件或执行 SourceGuard 建立 lease。

## 瞄准、开火、弹道与命中

物理按钮到武器 input logic/FSM、Zoom/Firing 组件的当前实例路径尚未闭合。已发现 `CanAimOn/CanZoom/CanFire` 等真实 native 声明，但不能把函数名或惯用鼠标按键当作本次已核验的输入绑定，也不能把瞄准动画当服务器接受开火。

最新 `owned-weapon-state.json` 中两把 Modular 的真实 cache exclusive maximum=58，候选入口及 checksum 为：

- `RPC_RequestServerHitAction` index42 / 2055839940：DamageResult，struct getter `0x5f47c40`，native params 856 bytes；反向 `RPC_ClientApplyHitAction` index40 / 2672446825，失败 index41 / 923004017。
- `SendReportClientHit` index45 / 2427976662：Guid、LatestTrajectoryItem、BlockingHit、RelativeLoc、RelativeLocToBone、TakerWeaponIdentity；native params 224 bytes。
- `ServerProcessWeaponEventDataForFire` index49 / 1966811592：FireEventParam，getter `0x60f9170`，native params 608 bytes，函数参数声明 `0x1cd6b050`。
- `ServerProcessWeaponEventDataForHit` index50 / 2177146757：BulletHitInfo，getter `0x218f2d0`，native params 208 bytes，声明 `0x1cd6b0a0`。
- Pawn 也有独立 `RPC_RequestServerHitAction` index91（max291），不能将 Weapon 的 index42 套给 Pawn。

这些是具体 owner/Actor 协议候选，不是已完成的 codec。各结构的 native 内存 offsets、FHitResult 和 trajectory 的自定义 serializer、字段 presence、版本、嵌套 NetGUID、量化与条件分支仍需从原生 archive 追完，并用保存的真实请求重放到精确 EOF；不得 memcpy native params。

当前 dfserver 生产源码对上述 Fire/Hit 名称没有 handler；未知 owning body 的传输接收/ACK 不执行射击。WeaponReplicate 的真实输出候选已观察：max25，MulticastFireEvent index8、Reliable index10、MergedFireEvent 11/12、MergedHitInfo13、RepHitInfo16，另有 OBAmmoDataInfos19/OBAmmoNum20；它们各自仍需 serializer 与 owning/observer 语义，OB 字段不能直接当本地拥有者弹药源。

本地权威层应从已接受的位置/姿态、同局 current weapon、实际枪配件/弹种、射击序号、服务端时钟和弹药余额决定是否开火，执行射速/装填/死亡/武器归属校验，再计算弹道或射线、遮挡/命中部位及伤害。客户端 Hit/DamageResult 只是报告，不可直接给目标扣客户端自报伤害。若使用本地射线、简化后坐力/散布或单独碰撞模型，须明确配置及覆盖范围；原版伤害验证/回溯/穿透/跳弹/材料/距离衰减尚没有完成证明。

结果必须先写同一局 shot/ammo/health revision，再投递真实 fire/hit/生命状态反馈；同 shot、重复 hit 或重传不能重复消耗/伤害。最终弹匣、备用弹、配件及磨损进入结算。验收包含射墙/遮挡、空枪、不同弹种、射速边界、重复命中、切枪/换弹并发及重新连接，不能仅验枪口火花。

## 装弹、卸弹与弹药守恒

`WeaponReload` getter `0x60fb0a0`、`WeaponCancelReload 0x60fafe0`、`WeaponCancelReloadSingle 0x60fb010` 是 local native 函数，不能因为名称就按 RPC 发送。实际已声明 `ServerProcessStageReloadResumeData` index47 / checksum201844041；getter `0x60fa0b0`、Params `0x1cd6afb0`，StageIndex、StateEndTime、RemainTime、TransitionTime 的 native offsets 为 0/4/8/12。它是分阶段恢复数据，尚不能认定是所有枪械重新装填的唯一入口；Firing/ChangeClip FSM 及弹药数据组件仍需追。

另一条是背包卸弹：InventoryManager max53 的 `ServerWeaponUnEquipAmmo` index51 / 549358845，getter `0xcfb4430`、Params `0x1d2384d0`，字段 GunGid、Num、InPutInSafeBoxFirst（bool 数组）、InAmmoToEquipGid。返回 `ClientNotifyUnEquipAmmo` index25 / 2284904939，含 UnequipAmmoResult 和 ResultCode。数组 inner、bool、各 presence、结果结构仍待 codec；背包卸弹与战斗换弹不能混为一个动作。

恢复依赖真实武器 magazine/节点、`weapon_ammo_catalog.json` 的枪弹关系和容量、局内可取弹 GID/位置、弹种、枪膛、换弹阶段与计时；规则应统一消耗/转移，不能一边更新 GunDesc、一边在另一套库存里另增子弹。当前已接初始 20 发等快照投影，不等于实现后续射击和换弹状态。装/卸/取消/中断/满弹匣/库存不足/装入另一弹种/死亡时中断均要验数量守恒及原生 HUD 一致。

## 伤害、防具、异常状态与医疗

Health 和防具不是同一数值。既有真实 `GPAttributeCenterComponent` 的 SpawnedAttributes+0x140 是 Net，StaticAttributes/InitGroupsNames 是非 Net；正常 Initialize `0x2fe0510` 从静态类及 provider 建 set，OnRep `0x2fe1e50` 为 Role1/2 重绑 provider。Health provider `0x3e05a10/0x3e45590`、GPAttributeSetHealth getter `0x5f90100` 有来源。客户端已有 Health=MaxHealth=100、Shield=0 可能来自正常本地构造；它不证明权威生命/伤害已初始化。不能把半条 HUD 改成 200HP。

原生单件物品 wire 已区分 ItemDurability/Max（native offsets64/68，selector `0xc0605bd`，max>0）和 ItemArmorHealth/Max（84/88，selector `0xc060667`，max>0）。真实 EquipmentFeature 从 C++ 分开读两组；业务 prop.health/health_max 不是护甲即时血量。只恢复初始耐久或大厅维修不能替代战斗护甲承伤。

真实热更 BodyArmorFunction row11050006004，uexp serialized offset51225，明确 MaxDurability=150、MaxArmorValue=150、ArmorLevel=6、DamagedDurabilityRate=1、DurabilityFormula=1001、部位 mask14 及 BuffOps。这证明存在多套状态和公式引用，不证明本地服务可按“减同样伤害”处理。热更 uasset SHA256 `24f2148bb917dfa2610093839fb5f5f21aa4eb80cf0658875f58177a198e3a65`、uexp `2af95b46e991dd0375622de42b3245d9c0d210dc2dbe7a34f3d0cf3351e330b1`。旧仅含 MaxDurability 的大厅目录不足以恢复防具公式。

本次重新从安装 PAK 读取并匹配哈希的医疗链：

- `SOLHealthSystemLogic.lua` SHA256 `1c60ce649d8569bf1e42c7a6fc34eca167b9b221f05d6a08ae9327fee41f8494`，entry29059072。函数0.16（源码320–354）取 GameFlowManager.GetCharacterInventoryMgr、选中物品 GetRawCppInfo，验证有效后调用 `AttemptUseItem(rawCppInfo, selectedPart, EUseItemInputSource.Health)`；0.17（356–359）取 UseItemManager 后 `AttemptCancelUseItem(0)`。
- `MedicineRouletteMain_HD.lua` SHA256 `ecd62548e7e505f1b9b7f1e2215ed278fb255e28e18072d25516a681dd3dc8c4`：0.22（486–501）依赖真实角色/UseItemManager 后调用 RouleteeSelectItem(gid,id)，0.23（503–537）检查选择及 IsItemLocked 后调用 DoUseItemWrap。不能只实现 health UI 的一条入口。
- `HealthFeature.lua` 0.4（46–55）从 ItemDurability/Max 初始化消耗品耐久；0.5（57–101）读取真实 HealthInfo 的 HealAmount、HealArmor、Durability、MedicalDurableType。单次用品、耐久用品、部位治疗、防具维修不能统一减物品数量1。
- `LootingServer.lua` 0.88（2543–2578）消费 PreUseItemInfo 的 UseItemState、UseItemGids、NextReloadExtraDelay、BulletCoolDown；`GameInventoryHealthPanel.lua` 0.3（32–83）通过 DFMHealthDataComponent 获取各部位 Health/Max。仅改总血量不会闭合这些消费者。

最新原生 cache 给出 UseItemManager max19：PreUseItemInfo index7、ClientCancelUseItem8、ClientFinshUseItem9（原名拼写）、ClientNotifyUseItemFaild10、ClientPreUseItem11、ClientStopUseItem12、ServerAttemptCancelUseItem13 / 3477101170、ServerAttemptUseItem14 / 2413196746、ServerRouleteeSelectItem15 / 2545204173。以下离线补查已闭合 UseItem/Cancellation 的 UHT 参数及基线 native wrapper 调用边；完整 wire、原版权威医疗和客户端成功验收仍未闭合。RouleteeSelectItem 到其 RPC 的独立调用链继续保留缺口。

### 医疗协议补查：实际参数与调用边

复现脚本是本会话新建的 [research_medical_contract_20261020.py](../work/research_medical_contract_20261020.py)，扩展反射研究后的 SHA256 `228282774e5a268201d06998a2bb4a9cd888c8c0b2d6a919f3be67e1ca34a521`（首轮1728f50a版本的asof哈希保留于JSON）。它只读固定 PE 声明数据和原有 code cache，不调用游戏代码，默认打印声明，`--rva/--bytes` 打印最多8192字节的反汇编，`--target/--call-target` 只给待进一步反汇编确认的引用候选；新增 `--reflection` 验证通用构造/建链/serializer。用根 venv 和 `PYTHONDONTWRITEBYTECODE=1` 执行；完整 record/field/hash、enum 表和 native code range pins 已保存到配套 JSON 的 `medical_protocol_followup` 与 `medical_reflection_followup`。

`InventoryUseItemManager` ClassParams `0x18859790`（80字节，SHA256 `a48dd50b1acb4fc3bfedb22505b7021f377e7f028107caf31d05fa46584b1c42`），StaticClass getter `0xcfc5430`，68个函数、36条属性记录。这里的 UHT `property_count` 会包含 enum 的 UnderlyingType 辅助记录，不能把它们当多个 RPC 参数。

- **使用请求14：** getter `0xcfc5c80`，Params `0x1d23d9c0`，SHA256 `6c4a2616efd5a19398ecbac9d169737317213000e6687691cb7093f77046f6ff`，flags `0x220cc0`。三个逻辑参数是 `ItemGid:uint64` native+0、`UseItemArgs:FUseItemArgs` +8、`ClientAnimTime:float` +0x40；native params占72字节。传入整个 ItemInfo 是 local AttemptUseItem 的接口，实际 RPC 只发送其 GID和独立参数，不能把2048字节 ItemInfo 当医疗请求。
- **取消请求13：** getter `0xcfc5c20`，Params `0x1d23d970`，SHA256 `d07d5674902bfd26d8396db566e6737be96583173dda1489b2a23d44fe9f7b2c`，同 flags。唯一逻辑参数是 byte-backed `ECancelUseItemReason Reason` native+0，params占1字节。explicit enum表 `0x18859e50` 的22项为 None0、Fire1、Aim2、VehicleAim3、VehicleNonWeaponFire4、SwitchWeapon5、BothTry6、ProneMove7、ProneToOtherPose8、TipHud9、MatchEnd10、Looting11、BackgroudCancel12、FinshPeriodUse13、SprintButton14、BeingCrocodileBite15、FaildToUse16、SkillHit17、InvalidLocation18、NotPassVerify19、SwitchSeat20、FourthVehicleSkill21；拼写按源保留。不能把取消只当UI按钮，战斗中断有独立来源。
- **嵌套参数：** struct getter `0xcfc5fe0` → StructParams `0x1d23c610`，SHA256 `bf110801b78e90aeaa8be3a6a03b99a2c5e95e238129161ffbf4cb67b3ae62e6`，native56字节、alignment8。真实字段为 Target（weak-object，+0）、Part（ECharacterPart，+8）、bUseOnHelmet（bool，+9）、bUseOnArmor（bool，+0xa）、TargetItemGID（uint64，+0x10）、TargetItemID（uint64，+0x18）、UseItemSource（EUseItemInputSource，+0x20）、PutInSafeBoxFirst（bool数组，+0x28）。这是内存字段身份和 offsets，不是连续网络字节。输入来源 explicit enum表 `0x18859c30` 为 None0、Health1、Bag2、Shortcut3、Rouletee4；来源值本身不授予治疗权限。Part表为 None0、Head1、Thorax2、Abdomen3、RightArm4、LeftArm5、RightLeg6、LeftLeg7、FullBody8。

**健康 UI 到真实拥有者 RPC 的基线链：** `SOLHealthSystemLogic.lua` 0.16 → `GameFlowManager.lua` 0.24（388–394，SHA256 `8b22a0bd86af814a69246b7d095028017f0294be58522a04e1fc969d045ce042`）→ `InGameController.lua` 0.18（189–194，SHA256 `c944d3f0600f7bb990773776b93ab0db43ac1a13156a1ecf74af107c77e6ab36`）。后者 upvalue 明确为 `UInventoryManager`，调用其 Get(character)，因此还需要 InventoryManager 转发层：native exec `0xcfb7c30` → `0xcfb7d46 call 0xbf51660` → `0xbf5196f call 0xbffda20`。UseItemManager 自身 AttemptUseItem 的 exec `0xcfc72a0` 也在 `0xcfc73b6` 调用同一 `0xbffda20`；它把 Part/InputSource 装入 UseItemArgs，再于 `0xbffdbc5` 调 `AttemptUseItemWithArgs 0xbffdc00`。后者一个已确认分支于 `0xc002e02` 调 RPC event wrapper `0xcfc6bf0`，该分支 ClientAnimTime 明确置0；不把此值推广到其它调用分支。

event wrapper 从 FName global `0x1e1042a0` 取 ServerAttemptUseItem 名，经 `0xcfc6c7a call 0x10eaa0c0` 找函数，`0xcfc6c8a call [vtable+0x220]` 进入 ProcessEvent。注册 exec `0xcfca3b0` 读取 GID/struct/float，在 `0xcfca532` dispatch到实现虚表+0x428；这不是已经恢复原版 ServerAttemptUseItem_Implementation 的判定逻辑。取消链是 `SOLHealthSystemLogic.lua` 0.17 → UseItemManager local AttemptCancelUseItem → exec `0xcfc7220` → `0xcfc7286 call 0xbffbdb0` → 非本地权威分支 `0xbffd96f call 0xcfc6bb0`；wrapper 通过 global `0x1e104298` 找函数，`0xcfc6bdb` 走 ProcessEvent，注册 exec `0xcfca330` 在 `0xcfca399` dispatch到+0x418。上述 native 函数含热修复 hook/角色分支，此次未观察实际执行或全部 override 路径。

**首轮 serializer 边界与后续提升：** UseItemArgs CppOps工厂 `0xcfc6100` 指向 vtable `0x18859d20`，RepItemInfo工厂 `0xcfc5000` 指向 `0x1885a7c0`；二者 slot+0x60（HasNetSerializer）及+0x70（NetSerialize）均为 false stub `0xd5f3a0`。进一步追构造和通用 serializer 后，取消的5bit Reason、presence、None 默认和参数 EOF 已闭合为下面的离线 codec；使用14的 parent/leaf顺序也有实际建链来源。实际医疗实例的 RepLayout/引用映射、原生请求重放、权威医疗和结果验收仍独立未完成。

**起止/结果与消耗边界：** PreUseItemInfo 是 component+0x2d0 的 RepItemInfo，property record `0x188592c0`，OnRep_PreUseItemInfo，cache index7不等于普通 handle。struct getter `0xcfc4f50` → Params `0x1d23c930`，SHA256 `7d515b869444fccd5c001b72ea7759a87bd0344b71b38733eb606866c04a3793`，native112字节，实际含 TimeToUse+4、UseItemState+8、PreUseItemGID/Id+0x10/0x18、UseItemGids/Ids数组+0x20/0x30、ItemStartUseTimestamp/End+0x40/0x44、WantUsePart+0x48、TargetItemGId+0x50、动画/后台标志和NextReloadExtraDelay+0x6c。名字 bValid 的+0字段在UHT为gen0xa（float），不能凭名字按bool编码。状态 explicit enum是 None0/PreUse1/Holding2/Using3/AfterUse4/Finish5。

结果 UHT也已核实：ClientPreUseItem 的参数为 ItemInfo（native+0）、RepItemInfo（+0x800）、Part（+0x870），native2168字节；ClientFinshUseItem仅bool bFinished，ClientCancelUseItem无参；ClientNotifyUseItemFaild 为 ItemId:uint64、ItemGid:uint64、Reason:byte；ClientStopUseItem为对象引用 Inv。原生大小均不等于 wire长度。LootingServer 的真实 OnRepUseItemInfo 消费者已匹配，但何时开始/完成、每个医疗品的数量或耐久扣减、分段/周期治疗、失败回滚、取消后的实际效果保留和库存delta都没有从本次缓存追完。现有物品配置字段和这些时间戳只能确定需要哪些状态，不能编造服务器扣药/回血公式。

下一步可执行的最小接入是先给真实 UseItemManager subobject 的13号取消请求建立严格 schema：核实当前 field/checksum/owner、单 Reason 的反射序列化和 EOF，再接同局医疗任务取消及正确 client result；14号另核验3个 parent和8个逻辑 struct字段。完整医疗必须在权威完成点原子提交 health/part/armor/buff与物品消耗，再发正确状态/结果及库存更新，并原生验成功、拒绝、打断、取消、重复/重连和退出结算。此轮只增加离线契约证据，没有增加 handler或医疗成功证明。

本轮复现核对15个函数声明、2个struct、4张enum表、12段native code哈希和全部2个文档本地链接。新医疗 helper来源pins全部匹配；历史非医疗 `portable_source_guard.py`、`legacy_ds_control_connection.py`、`game_server_probe.py` 的3条pin已发生其它会话工作带来的变化，JSON保留旧asof并另记当前值，本轮未重新审计其运行逻辑，不能用旧pin宣称当前整套runtime再次获得资格。

### 通用反射编码补查与取消参数 codec

这轮新增 [medical_cancel_codec_20261020.py](../work/medical_cancel_codec_20261020.py) 和 [test_medical_cancel_codec_20261020.py](../work/test_medical_cancel_codec_20261020.py)，只处理独立的13号 RPC 参数 body。`source_schema()` 实际只读验证原始 PE、固定 code cache中的30段代码、40段声明/虚表、62处指令锚点；`encode_cancel` / `decode_cancel` 不连接服务、修改物品、取消任务或发送结果。

**参数顺序有构造和链接来源。** `ConstructFProperties 0x10ea37f0` 在 `0x10ea3855` 把 UHT指针数组前进8字节；enum/array分支递归消费一条 underlying/inner记录，结束时扣对应record计数。这些辅助记录不会成为独立 parent。FProperty constructor `0x10e3e530` 经 owner虚表+0x258调用 `0x10cf7980`，后者执行 new.Next=owner.ChildProperties、owner.ChildProperties=new，反转UHT逻辑属性顺序。`InitFromFunction 0x12db2cb0` 从 function+0x70 遍历，以 flags&0x480==0x80选择参数，再于 `0x12db2e16` 建叶子。于是取消确实只有Reason；使用14确实是 ItemGid → UseItemArgs → ClientAnimTime，不能把声明表中首先出现的 ClientAnimTime 先写到网络。

**None 默认值已追到真正的清零来源。** Cancel Reason构造为FEnumProperty，class flags `0x1000000008001` 不含Bool专用 presence bypass位0x20000。普通接收器 `0x12db9679..96e1` 读一个presence位，false直接跳过该parent。FEnumProperty LinkInternal（虚表+0x70 → `0x10e272c0`）在 `0x10e27301..2730b` 补 property flags `0x1040000200`，其中含ZeroConstructor bit9；`InitFromFunction 0x12db2eb3` 因此置parent flag0x40，接收器 `0x12db943d..9443` 会跳过该parent的单独初始化。保持零值的真正来源是上层 `0x128932e9` 取UFunction尺寸，`0x1289336a..93372` 把整个参数buffer r14 memset0，随后 `0x128933ad/933b7` 传给RPC接收器。不能仅引用接收器里另一条memset分支就宣称enum默认值成立。

**5bit及EOF规则也有来源。** enum vtable `0x15a87070` +0x90 → `0x10e29fa0`，按archive版本>=12使用max+1计算bit数并调用SerializeBits。UHT enum创建 `0x10ea6203..621b` 启用自动MAX；UEnum::SetEnums `0x10e38300..3833c` 追加原max+1，因此取消的生成MAX=22，Part生成MAX=9，InputSource生成MAX=5，对应新版本5/4/3bit。取消参数有两种合法的None表达：`00` / 1bit（presence=false），`01` / 6bit（presence=true，Reason0）。Fire1=`03` / 6bit，Aim2=`05`，SwitchWeapon5=`0b`，SprintButton14=`1d`，FourthVehicleSkill21=`2b`，后面均为6bit。codec要求参数slice恰好1或6bit、物理存储为1字节、padding为0；截断、尾随bit、额外字节均拒绝。拒绝22..31是本地限定为explicit enum的语义策略，不能声称原生NetSerialize会自动拒绝所有未声明值。

**使用14的struct来源等价schema已明确。** CppOps的+0x60=false经 `PrepareCppStructOps 0x10d03fc5` 阻止 `0x10d0405a` 设置StructFlags0x400，所以该struct递归展开，不能发送56字节原始内存。`0x12d9b3d9..445` 取struct.ChildProperties并过滤RepSkip，`0x12d9b47c` 调 `0x4a24e50` 按Property+0x54 offset升序排叶子，同offset才比较名称，`0x12d9b54c` 递归。实际结果是 Target → Part → bUseOnHelmet → bUseOnArmor → TargetItemGID → TargetItemID → UseItemSource → PutInSafeBoxFirst，子叶没有各自的RPC parent presence。

- Target是 `FWeakObjectProperty` vtable `0x1ab610f0`，+0x90绑定 `0x10e8ed20`；其 `0x10e8ed44` 从weak内存取object、`0x10e8ed76` 调PackageMap+0x260、`0x10e8edc4` 回填weak。网络值经普通对象映射，不是弱引用的index/serial两整数。GUID0是null，已映射非default GUID只走packed-GUID分支；GUID1带flags、Outer、FString和可选checksum，不能当普通裸GUID跳过。既有只读 reader来源是 peer 的 `audit_skill_trigger_saved_packets.py:79` 及其 `native-skill-wire-default-guid-reader-v1.json`，本轮未将其接入医疗codec，也不创建或分配对象。
- Part是4bit、两个native bool各1bit、TargetItemGID和TargetItemID为两个普通64bit数、UseItemSource是3bit；这里明确限定archive版本>=12及normal no-byteswap数值分支。bool来源gen0x4c的bit6表明native bool；`FBoolProperty` vtable `0x15a868a0` +0x90 → `0x10e8ebe0` 在 `0x10e8ebfa/ec19` 调SerializeBits(1)。native bool占1字节不意味着网络占8bit。
- PutInSafeBoxFirst是动态bool数组。`0x12dc2125..212b` 先按unaligned raw uint16读取元素数，`0x12dc23c5` 逐元素递归到同一1bit bool serializer。数组count不是packed-int，也没有每个元素的presence。三个parent全部present且Target为null时，来源等价的body长度为260+数组元素数bit；这是源码推导，不是已保存原生医疗请求的实测长度。
- UseItemArgs的native Construct `0xcfc66f0` 明确把weak index=-1/serial=0、Part0、InputSource0和数组空写入；其它字段未写。RPC外层先清零buffer，后执行该构造，解释了absent parent的其它零值来源；不能把这个native ctor本身称为memzero56字节。

定向命令 `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=work .venv/Scripts/python.exe -X utf8 -m unittest work.test_medical_cancel_codec_20261020 -v` 已从缺模块的6项失败转为6项通过，覆盖22个原因、两种None、明确战斗中断hex和畸形slice。测试是离线生成fixture的精确EOF往返，不是原生捕获重放。当前可复用的是取消参数codec及使用14的来源等价schema；完整医疗接线仍要本次真实subobject/owner/field资格、对象引用映射、实际实例archive/RepLayout核对、权威任务/消耗事务、正确结果复制和原生UI验收。PreUseItemInfo普通复制handle与失败/完成结果codec没有被取消参数测试顺带证明。

本地权威要统一验证物品 GID、选中部位、健康/护甲/异常状态可用条件、占用/打断、服务端起止时间和取消理由，在完成点原子修改物品数量或剩余耐久、对应生命/护甲/部位/buff 状态，再投递 pre-use/finish/cancel/fail 及库存 delta。出血、骨折/肢体损伤、镇痛、体力/负面效果、持续治疗、驱散、buff 叠加/到期的真实配置/执行尚未闭合，必须分别恢复；不能用笼统加血冒充。死亡/撤离/断线只能结算已提交消耗，重传不重复治疗或扣药。

## 倒地、救援、死亡与掉落

GPCharacterBase 的 DeadInfo+0xdc8 为 Net/OnRep_Dead，StructParams `0x1cd074e0` 已有字段来源：bIsDead、DyingTime、DeadTime、DeathDirection/Pose/DamageType、ShotBone/RawShotPos、KillerUin/GUID、SourceWeapon、DeathLoc、ServerDeadTime 等。其 native fields 不等于已恢复线上顺序、bool bit、enum 或当前 AI 普通 handle，禁止原始 bytes 复制。

最新 Pawn cache 中 bIsBeingRescueReplicate index113、DeathWaitRescueTime_Custom176；PlayerState 有 DeathWaitRescueTime27、Start28、End29、bDeathWaitingRescueEnd31；PC `ServerNeedRescue` index222 / 1196715698。声明 Params 包含 InNeedShowRescueNum，不能据名字认为它就是完整救援动作。真正救援需要交互双方身份、队伍、距离、倒地状态、计时/取消与生命恢复；队友复苏和多人角色生命周期当前未实现，单人死亡策略不能覆盖它们。

AI BP 的 HealthComp cooked 默认 EnableImpendingDeathFeature=false，不能把玩家倒地机制套到全部 NPC。权威必须先决定“受伤 → 倒地/濒死 → 复苏或最终死亡”的合法转移，再复制已核实状态/表现；客户端自报死亡不能触发账户扣装或掉落。

PC 真实尸体交互 `ServerLootDeadBody/ServerPickupDeadBody` 是 AInventoryPickup_DeadBody 对象参数；普通开箱、物品移动另有协议。`BP_DeadBodyAmmoBox` 配置 AddWithPercent30、OnlyKillerTeam、override ammo，是弹药拾取器，不能冒充通用尸体背包。

一次权威死亡须唯一提交：冻结死亡原因/位置/装备 → 停止行动及医疗/换弹 → 给真实 corpse/pickup 唯一实例和有限物品归属 → 复制死亡/尸体/搜索库存 → 普通命令原子取物 → 本局结算。死亡重复事件、重传和重连不得创建第二具尸体或第二份枪。`work/portable_world_session.py:361/406` 已有终局冻结和同 SQLite 事务 materialize 的独立模型，但没有证明它是现行所有战斗/库存操作的统一生产 owner；还必须接账户 writer、revision 和 outbox，不能从原大厅快照重新“结算”。

## AI 巡逻、感知与战斗

可用真实 Pawn 为 `/Game/BluePrints/Characters/AI/BP_DFMCharacter_AI.BP_DFMCharacter_AI_C`，parent DFMAICharacter；AlwaysFall 子类也存在。基础 uasset/uexp 哈希分别为 `b9fc0f4ee3937d33051e518b4a199a4bbf9d44c449056a4b6fba7aa37178d52b`、`8a4b27b85056c62ac303ec965a7d91e0d397b90a601420d43d936c52f0110c57`。CDO export10 的 bOpenAIActive=false，非 Net；不能向它猜普通 handle。移动 export15 的真实 MaxWalkSpeed500、MaxAcceleration2000、步高55、坡度45、ProjectNavMeshWalking=true 是 cooked 默认，不是服务器已拥有导航/碰撞。

已验证289个 PAK、1,179,117路径的资料定位到 BP_DFMAIController（chunk124、uasset encoded offset1348）及 `AI_SOL_V2/Drama_SOL/Patrol/Common/BT_Group_Patrol`（chunk73、offset5576）。存在性已验证，但上述 controller/BT 包的当前 authored defaults、blackboard、navigation data 仍未完整解析。普通 SOL_V2_AICharacterTemplate 精确资源及三个 Intro root/controller/Pawn 引用在该范围未找到；不能把 Intro13行表当完整普通大坝模板。当前大坝静态20组/29候选/28模板不能推出当局生成数量或可战斗 AI。

原生 spawn 可追：`ADramaArea::SpawnDramaAI 0x9e1d380` 检查 drama/prefecture/spawner；`AAISpawnChecker::LifeGiving 0x99fee70` 检查限量、模板 BP、DefaultController，投影有效地面、生成/possess 并绑定死亡销毁；模板 getter `0x9a6fa40`。AI Controller 的168个声明属性/123函数中零声明 Net property、零声明 Net function；OnCharacterDied 和 SpawnPickupById 是本地函数，不是客户端 RPC。不能给远端 simulated proxy 发一个 BT 引用就认为服务端巡逻/感知已运行。

AI Pawn 有17个 Net 字段/24 Net函数；bFighting+0x392c、RootMotionActionRep+0x3940、bAIWeaponHidden+0x3a30、PlanningTransitionRep+0x3a50、AIInfo+0x3ce8 等有真实来源，但 offsets 不是 handles，接收 schema 仍待普通构造/合格元数据核验。AIInfo 是48字节 SpawnBaseAIInfo，含 NpcTemplateTable、NpcName、SpawnLocation、BatchNum、Inx；不能用裸结构发送。NpcName 的普通 native OnRep 是 no-op，也不是已证明的完整模型初始化入口。

当前 Python 服务没有已证明可用的权威 AI 生命周期。必须使用同一局 accepted server positions、碰撞/导航与时间：生成策略/可落地 → 巡逻路径 → 感知视距/遮挡/听觉 → 警戒/追击/失去目标 → 瞄准/射速/弹药/射击 → 被击/生命 → 死亡及有限尸体掉落。决策、难度、感知参数和掉落可作明确本地配置；客户端真实模板、动画、复制和资源映射继续按来源恢复。服务端位置如果只是客户端坐标报告，不能据此给 AI 视线、交互距离或命中认证。

原生 Shipping 仅有 Standalone 骨架，既有 Listen LoadMap 指向返回 false 的分支；尚无证明可运行完整 Dam/session/loadout/AI 的启动命令。可继续只读闭合原生 authority 初始化入口，但现阶段不能用“Shipping 有函数”省略本地模拟，也不能断言所有 native authority 代码均不存在。

## 其它战斗分支与范围限制

- 手雷/投掷物：真实 Weapon ThrowMode、ClientToServerSetThrowMode index39、ServerToClientThrowModeVerify53 及 projectile 类线索存在。切换模式不等于生成、抛物轨迹、碰撞停止、引信、爆炸遮挡/半径、破片、烟雾、闪光/异常效果、销毁、有限物品消耗已实现。每种实际投掷物需独立 source-backed 参数/serializer/projectile 生命周期；不能复用子弹 hit 总伤害。
- 近战：真实 selected_melee 进入冻结快照，BP_EmptyHand 不是所有近战的替身；WeaponMeleeDataConfig 已提取，IsMeleeWeapon/point-hit 候选也存在。当前未闭合近战输入/动画窗口、服务端攻击序号、距离/方向/遮挡、目标/部位、冷却及命中反馈；不能把“已选择刀皮肤”记为可近战。
- BOSS/特殊兵：普通 AI Pawn 和 patrol BT 不能证明 BOSS 阶段、技能、装备、事件激活、专属掉落/任务或奖励。对应真实模板和本地状态机/结算是独立缺口。
- 队伍/多人：当前 single-player admission/slot 策略没有覆盖多人 possession、互相 relevancy、敌我判定、友伤、救援、共享/独占掉落、断线重连及全队终局条件，不能泛化成完整 SOL。

## 全玩法范围普查

本节补充 MP 与载具等范围，避免把 SOL 单人枪战代表所有模式。只核查现有模式配置、保存反射、当前安装真实 Lua 和当前 runtime，没有开展新的进程采样或无界资源逆向。新增24个不同 Lua 块均从同一安装 PAK 重读，逐块 SHA256 匹配并解析到 EOF；来源/entry/function 全列在[证据 JSON](../work/evidence/gameplay-combat-research-20261020.json)的 `all_modes_survey`。

模式来源须分层理解：`protocol/portable-map-spawn/world-state-schema.json` 由已保存原生 enum 来源恢复 EDFMGamePlayMode：SOL1、Raid2、IrisDiscovery3、Conquest4、Breakthrough5、SafeHouse6、Intro7、BombDefusal8、GoldenGunGun9；这不是业务 sub_mode，也不是所有模式当前开放的证明。既有 `native-gamemodeconfig-actual-rows.json` 完整解析基础 `/Game/DataTables/GameModeConfig` 四行：row1/offset71 为 SOL（PMC/SCAV/SOL），row2/972 为 PVE（Easy/Normal/Diffcult/RealWar），row3/2074 为 BigWorld，row4/3134 为 TDM。这张基础表与上述原生 enum 不同，且未在本节完成所有热更/发布地图板合并，不能按行号互换 enum 或宣称该表已列全当前玩法。

当前接线的模式边界很具体：`work/portable_map_world_state.py:40` 按名称选择 `GamePlayMode_SOL`。`hero_customization.py:268/280` 有保存的 mp_hero_selected 返回值，`handshake_diagnostic.py:1546` 返回 mp_level；它们属于大厅账号表现，不能证明 MP admission、MP Pawn/Controller/GameState、重生或团队规则已运行。本节对当前 dfserver 的命名 handler 搜索未找到载具、部署重生、占点/票数、MP装备预设执行；实际 owning 分派仍是已经审计的 startup、owner-switch、movement 和其它有界/不透明接收，不具备由 UI 名称自动执行 MP 规则的通道。

- **MP兵种、干员与装备包、部署/重生。** 真实 `BattleFieldPresetLogic.lua` 0.5（131–139）调用 ArmedForceServer.DoSaveMPPresetItemByBagIdAndSlotTypeReq；`BattleFieldSelectionDataLogic.lua` 通过 HeroServer/ArmedForceServer 和 PresetRow_to_PropInfo 组织选择。`BattleFieldRedeployView.lua` 0.12（212–222）将 armId、heroId、bagId 交给 SetCurrentHeroAndBag，再调用 native-facing RedeployBtnClicked，不能把它简化成 SOL 初始票据。`RedeployArmSelectedView.lua` 0.15（188–293）区分首次、预部署、等待部署等状态，监听队友点正在战斗/点位可部署事件；`BreakthroughRedeployPointVehicleHub.lua` 管理真实选中 VehicleSpawnAreaHub/VehicleType；`RebornFlagActorView.lua` 关联真实 DeployPointPanel 与 RebornFlagName。**未闭合：** RedeployBtnClicked 后实际 MP owning RPC/参数/receiver、MP专属 class cache/RepLayout、合法出生点/载具容量/冷却、阵营/小队、部署预设提交、重生资格/消耗/保护、再次 possession 和旧 Pawn 生命周期。当前 SOL 单次出生、保存 MP 干员或显示部署面板不能验收此链。
- **MP占点、突破阶段、团队票数/得分。** `BattleFieldRedeployView.lua` 0.8（102–120）先检查实际 GameState 和 `GamePlayMode_Breakthrough`，然后绑定 GameState.OnReceiveMulticastOccupyStatusChanged、onClientOnSectorActived、onCurStage。`BreakthroughSectorAnchorCapView.lua` 0.21（273–311）读取 CurCapturePoint、AttackerOccupyComparison、CurOccupyVal、AbsMaxOccupyVal；0.25/0.26（340–398）读取 Camp0CharactersNum/Camp1CharactersNum、OwnerCamp；0.31（506–517）处理真实占领通知。`MPScoreBoard.lua` 0.7/0.8（127–190）消费 team_id、队伍击杀和 BattleField/MedalPointTable；`MPScoreDetail.lua` 0.13（339–528）另消费绩效、胜负、阵营差等排位结果。**未闭合：** 真实 CapturePoint/sector Actor 与 MP GS receiver、服务器 accepted position/阵营进入判定、争夺/进度/归属/阶段转换、票数扣减/击杀/救援/占点事件计分、胜负与排行榜/奖励持久化。HUD消费者和局后成绩 UI 不提供权威计分算法，现有 SOL RealStart/HighValue 数组不能替代。
- **载具上下车、座位与驾驶。** `VehicleGetOnView.lua` 0.2/0.3（31–61）从当前 CurrentInteractorInfo.InteractableProxy.Interactor 取得真实载具交互器，GetParentActor 后按 CheckSeatTypeExist、IsSeatFull、IsLocalPlayerOnVehicle 显示座位菜单。这是具体真实对象依赖，不能凭空创建按钮或用模板ID当对象引用。保存原生 label RVA `0x19082d60` 还有服务器因 IsForbidInteractGetOn 拒绝 GetOn 的诊断；`native-economy-interactor-lifecycle-labels.json` 有真实 VehicleAnimInteractor 的 GetOn/GetOff 动画入口。**未闭合：** 此次尚无合格当前 Vehicle Actor/Seat/Movement/Health receiver，未闭合上车/下车/换座真实 tag/RPC参数及坐席占用权、驾驶输入/服务器物理、角色挂接/控制权/相机、下车可落地点、移动复制/纠错、死亡/断线释放座位。菜单和动画标签存在不证明服务器已有驾驶模拟。
- **载具武器、固定武器与工事。** 最新保存的 SOL Pawn cache 有 UploadVehicleTerrainRaycastResult262/checksum1930869653、Client2ServerWeaponBipodDeploy271/2640181917、ServerAirDropVehicle275/1467171337；通用 PlayerState cache 有 RequestCommanderVehicleDeployApproval128/2701934844、RespondCommanderVehicleDeployApproval131/4109845416、ClientCommanderChangeSeat114/591288275。这些是在 SOL 实例上观察的继承/共有入口，不是 MP载具专属布局或已接受请求。原生标签另有 `ABattleFieldCharacter::ServerApplyWeaponItemModifyInFirstRedeploy`（字符串RVA `0x19d0c000`）、`AFortificationProxy::OnRep_FreeBuildFixedWeapon`、`UMapInfoSystem::OnRep_SkillFixedWeaponWhiteModelInfo`、VehicleWeaponAmmoCountChanged。**未闭合：** 当前可用载具/固定武器资源绑定、部署配额与控制座位、炮塔瞄准/射界、载具专用 ammo/fire/projectile、固定武器交互/占用、建造/摧毁、工事归属、服务器命中及结果接收；字符串或支架展开入口不能算完整固定武器。
- **载具损伤与修复。** 原生资料有 `UInteractorRepairComponent::ServerStartInteraction/ServerEndInteraction` 注册标签，但本次没有闭合其实际车型/功能和修复参数；当前 SOL 的 `ServerRequestRepairItemProgress` 是独立物品修理入口，不能直接称为载具修理。`VehicleServer.lua` 0.9（83–98）实际发 CSMPGetVehicleDataReq、0.10（101–121）发 CSMPChangeVehicleSkinReq、0.11（124–142）发 CSMPModifyVehicleReq，后两者填 vehicle_id/skin_id或part_id/unmount/sub_mode，是大厅载具拥有/皮肤/配件链。**未闭合：** 载具及部件生命/装甲/弱点、乘员伤害、爆炸/燃烧/失能、维修工具/资源/距离/队伍/计时/打断、维修结果复制、销毁与残骸/重新生成；本次没有取得足以实现这些行为的当前 VehicleHealth/repair wire，也未找到对应生产 handler。大厅改装不能替代局内维修。
- **团队救援与其它模式。** 通用 PC ServerNeedRescue222 及角色 OnServerGPCharacterBeingRescue/RemoteRescue、OnClientCharacterReborn/OnServerCharacterReborn 等源成员已存在；这些 OnServer/OnClient 名称中多项实际是非Net委托，不能当 RPC。`BreakthroughTeamInfoHUDView.lua` 0.4（53–76）的 BeingRescue/部署状态是显示门槛。仍缺 MP/队伍真实救援交互/权限、倒地计时、复苏/拖拽/远程救援/得分、队友重生点的战斗禁止条件。BombDefusal/GoldenGunGun 的原生模式枚举存在，Raid/IrisDiscovery/PVE/BigWorld/TDM 也有配置线索；本节尚未核实这些模式各自的关卡/规则/装备/回合、拆装目标、专用升级规则、团队得分或独立终局协议，必须分别登记待恢复，不能改一个 SOL mode enum 就开放它们。

新增接线必须先确定模式的真实 GameMode/GS/PC/Pawn/规则配置和地图，而后恢复该模式的原生 receiver/输入协议及本地 authority。跨模式可共用已经验证的传输、身份、库存守恒和伤害 ledger，但每个模式的部署、复生、兵种/预设、阵营、小队、目标、计分、胜负、载具/固定武器生命周期和结算都需自己的显式状态与验收。原生验收至少分别完成一轮 MP“选择兵种装备 → 合法部署 → 占点/击杀/救援计分 → 死亡/重生 → 胜负/结果”，以及“载具部署/上下车/换座 → 驾驶/武器 → 受损/修复/摧毁”，不能由 SOL 一轮带出记录替代。

## 可执行恢复顺序与原生验收

1. 保留现有真实 snapshot/recipe/初始化进展，先完成合格 appearance 观察及正常挂接回调；独立观察实际切枪输入区间，记录 owner field/disposition，而非只读总计0。
2. 沿既有 Actor/Pawn owning assembler 做单一战斗 dispatcher，只注册经过 source/hash/owner/subobject/field 资格的协议；Fire/Hit、Reload、UseItem 各自完成 struct serializer 和真实捕获 EOF 重放，未知内容继续有界保存。
3. 建同一 admission 的权威 combat state/revision：位置/姿态、current/pending gun、枪膛/弹匣/备用弹、HP/部位/护甲/buff、医疗/换弹任务和死亡状态；明确以已接受 movement authority 为前置。服务端 shot/timer/transaction 做去重，所有输出走既有实际发送及 ACK outbox。
4. 完成普通枪射击/遮挡/伤害/防具及各弹药操作，再接医疗/异常状态/倒地复苏/死亡。扩展投掷、近战、技能伤害时使用同一个 damage/ownership ledger，各分支有真实参数和独立验收。
5. 接普通 AI 的有效 spawn/外观/移动 receiver，实施完整本地巡逻/感知/战斗/死亡/掉落；随后独立补 BOSS、特殊兵及队伍协作，不用静态模型充数。
6. 将弹药、药品、护甲、掉落及物品移动都接到同一持久局内 ledger；终局 commit/materialize 和账户 writer 同事务，原生 match end 只在提交成功后发送。
7. 原客户端逐操作记录至少：两把实际枪及皮肤/手部持续可见；切换/瞄准/开火；换弹/卸弹/取消；墙体遮挡及目标掉血/护甲变化；医疗成功/失败/取消与消耗；一个真实移动、感知、反击、可杀死且可搜刮的 AI；死亡/救援分支；撤离带出并退出重开。每个操作关联 native request、权威前后 revision、投递及客户端消费者结果，另验重传/重连不重复消耗、伤害、掉落或发奖。

本次离线核验覆盖原七块及跨模式新增24块安装 Lua 的解析及 SHA256匹配、当前生产 caller/缺少 handler 的定向搜索、最新保存对象的字段级区分和来源哈希。没有运行新原生验收；以上所有未闭合项继续保留未完成，不能用本报告、单元测试、已创建对象或 ACK 替代完整可玩证明。
