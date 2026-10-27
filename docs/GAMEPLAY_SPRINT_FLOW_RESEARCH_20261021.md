# Sprint 输入、移动意图与权威执行边界

研究固定时间：2026-10-20 16:55:36 UTC，即北京时间 2026-10-21 00:55:36。只读原安装、既有冻结代码缓存与协作者仓库；只在本仓库新增本报告、JSON 证据和只读查询脚本。未启动游戏、访问进程、操作 shadow、发包、访问数据库或修改协作者文件。本轮是源代码契约研究，没有冲刺功能验收。

原生镜像 SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`；缓存 `1792259162856698600` 的 manifest SHA256 `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。26 份文件、21 段代码和 6 段原盘记录独立固定在 [JSON 证据](../work/evidence/gameplay-sprint-flow-research-20261021.json)。缓存函数范围的字节闭合不代表整个函数的业务语义已恢复。

后续[体力处理补查](GAMEPLAY_SPRINT_STAMINA_RESEARCH_20261021.md)已闭合重复启动SprintPenalty的真实请求参数、独立与持续两种配置类型、组件tick到持续更新及恢复计时片段。下文把这些项列作未知的是原采样背景，应按补查缩小剩余范围；完整当前模式参数、全部门槛和结果复制仍不能由意图位推导。

另已找到[BP默认组件的具体配置](GAMEPLAY_SPRINT_STAMINA_CONFIG_RESEARCH_20261021.md)及[惩罚开关、阈值和负重曲线来源](GAMEPLAY_SPRINT_STAMINA_POLICY_RESEARCH_20261021.md)。Penalty注册默认开关为0，当前覆盖未观察；持续配置系数和曲线键也不能直接当作本局最终体力结果。

## 1. 已恢复的具体契约

`bWantsToSprint` 是移动组件原生 `+0x9b0` 的独立字节。UHT record `0x16662d48`、SHA256 `179f829a353e0f593939cacc4863a62fdedb424231540b973299838f6387ecf1`；setter `0x5fc8770` 的 `c681b009000001` 即 `[rcx+0x9b0]=1`。其属性 flags `0x10000000000014` 不含 Net 位 `0x20`，不能给该成员发明普通 Net handle。

冲刺意图位已经有生成与消费两侧的原指令依据：

1. `0x475fa50` 的正常 saved move 捕获，在 `0x475fb54` 读取 movement `+0x9b0`，`0x475fb5b` 写入 saved move `+0x369`。函数绑定的原盘类型文本是 `FSavedMove_GPCharacter`，不能将这个 `+0x369` 当成移动组件偏移。
2. saved move flags 生成函数 `0x469b7e0` 在 `0x469b85d` 先 OR `0x4`，`0x469b860` 比较 saved move `+0x369`，`0x469b867` 在零时恢复未置位值。因此其第 2 位为冲刺意图，mask 为 `0x4`。
3. native flags 消费函数 `0x47d7840` 在 `0x47d7925..0x47d792c` 执行 `eax=edx; eax>>=2; al&=1; movement[0x9b0]=al`。清位同样有真实语义，即请求停止该意图。

`GPMoveParams.MoveFlags` 在原生结构 `+0x10`，是 wire 中的连续 32 bits。当前 native `NewServerMove` 实现确实读取该字段，并沿第 3 节的当前 SOL 分派将其送入上述消费函数。因此 `MoveFlags & 0x4` 的解释有来源支持。这不表示一包含该位就已开始奔跑、消耗体力或得到权威确认。

尚未闭合 saved move flags 返回值写入发送端 `GPMoveParams.MoveFlags` 的精确 store/callsite，也没有本轮自然 Shift 按/放对应的实际原始请求切片。因此保留“意图位与接收语义已恢复”和“完整实际发送时间链已验证”的区别。

## 2. 输入与作者动作

本轮重新验证了输入消费者 `0x4eeb740` 的 39058B 缓存范围。正常输入路径的 `0x4ef0831` 取黑板 `+0xd98` 位数组，`0x4ef083a` 调用 first-set helper `0x32e28e0`，`0x4ef083f` 要求返回 `-1`。`0x4ef1109` 调用 GPSprint `CanSprint 0x44c1a70` 后，`0x4ef1118/1125/112e/1137` 还检查数个局部条件，才在 `0x4ef114b` 调用当前输入对象 virtual `+0x480`。

这些 `rbp+0x1110/1108/1118`、`rsp+0x70` 是该函数的临时栈值，不是可复制的 Pawn 属性或权限位。本轮没有恢复它们与实际 pressed/released、按住/切换设置和输入来源的全部 reaching definitions，也未资格化 virtual `+0x480` 的确切接收类/目标。因此不能简单把 Shift 按下等同于 `StartSprint`、释放等同于某个猜测 RPC。

实际 `AtomFSM_BasePose` 包保留了 SprintCheckAction、SprintExecuteAction 模板。`.uasset` SHA256 `95e0c09676920b74fd3c714b72e66875bc693b7b63b6fde1efa0ccad1bd4dbba`，`.uexp` SHA256 `c8e45083657a59d09b8495378a5ef54f7b27bd59c86f30448d8451e9d31ecffd`。既有包解析证据包含 Pawn `OnFsmTransitionEvent` 的 event 7/8/6 转移入口；轮询条件为 AlwaysFalse 不能单独证明事件转移不可达。本轮未观察当前实例活动节点或自然按键时序。

新恢复的原生动作身份是具体的：`DFMFSM_SprintExecuteAction` static getter `0xce8aa50` -> constructor `0xce8bb70` -> primary vtable `0x186b1e70`。原盘 slots `+0x330/+0x338/+0x340` 分别是 `0xab8a250/0xac85270/0xabfdbb0`。在这些实际类方法范围内：

- `+0x330` 方法在 `0xab8ac12` 将角色 movement `+0x9b0` 写 1，在 `0xab8b99e` 将所取 Sprint 对象 `+0x102` 写 1。
- `+0x340` 方法在 `0xabfe552` 将 movement `+0x9b0` 写 0，在 `0xabff2e1` 将 Sprint `+0x102` 写 0。
- `+0x338` 方法 `0xac85270` 读取 Sprint `+0x102` 并执行作者动作的持续更新分支；其全部时间/属性规则尚未恢复。

这些是作者 Sprint 动作中真实存在的起止写入，不能据此省略外围资格检查、动作生命周期、属性请求与回调。此处按真实 vtable slot 标识方法，未把共同动作基类 ABI 的方法名当作本轮独立恢复结果。

## 3. 当前 SOL 原生接收分派

`NewServerMove` 的 UHT params `0x1cd08550` 为一个 248B native struct 参数，flags `0x80220c40`，是 C->S unreliable；248B 不是 wire 长度。native registration 表 `0x16666e60` 的真实 name/exec pair 将它绑定到 `0x5fcb570`。

exec 在 `0x5fcb5f1` 调用 `+0xb98`，返回 true 后才于 `0x5fcb624` 调用 `+0xba0`。已核对当前真实 `/Script/SOL.SOLPlayerMovementComponent`，没有把 GP 基类的 vtable 假定为派生类：

```text
SOL getter 0x104d2e50 -> ctor 0x104d41e0 -> vtable 0x1a8f12d0
  +0xb98 = 0x46d0ef0, +0xba0 = 0x46d01c0
  +0xa40 = 0xb0483e0, +0x9e8 = 0x48367c0, +0x9f0 = 0x47d7840
```

`0x46d0ef0` 是完整 23B leaf：执行参数 `+0xe0` 的清理调用后返回 1。这不是 sprint/stamina 资格判定。具体执行路径仍有下游门槛：

```text
0x46d01c0: 0x46d0e04 读取 Params+0x10 的 MoveFlags
            0x46d0e1c -> virtual+0xa40
0xb0483e0: 0xb048537 -> 0x476eeb0
0x476eeb0: 0x476f04b -> 0x12738170
0x12738170: 0x127386a8 -> virtual+0x9e8
0x48367c0: 0x4836879 -> virtual+0x9f0
0x47d7840: 0x47d792c 写 movement.bWantsToSprint=(MoveFlags>>2)&1
```

这是当前 SOL 正常分派中可达的源路径，不是无条件执行证明，也没有执行 native 方法。`MoveAutonomous` 段在 flags 更新后还调用 owner 和运动处理的其他虚槽；本报告没有恢复完整碰撞/速度积分或权威纠正算法。

## 4. 线格式与当前便携实现

当前 [wire decoder](../work/portable_movement_wire.py:141) SHA256 `83847fc65303e26755d4946682ceb73b56ccba817d9b860aac183ce701fd68dd`，独立重新读取的正常 grammar 为：struct presence，timestamp f32，packed10 acceleration，MoveFlags u32，View u32，packed100 location，roll u8，move number u32，packed mode u8，packed100 velocity，extension flags u8。必须精确 EOF；非零 extension 仍拒绝。flags bit2 与 extension bit2 是不同域。

真实 field index 为 movement component 的 `6/max10`。绑定必须来自本次 admission 的 Pawn、`CharMoveComp` 和组件 GUID，不能固定历史 GUID；C->S 内容没有 S->C stable-name selector 位。当前 [binding](../work/portable_movement_binding.py:67) 已提供这层资格检查。

本轮重新读取全部 [movement runtime](../work/portable_movement_runtime.py:26)，SHA256 `2b0a80f96a8f73995a5b6b98b6a015df680415bcccfb8f76ae7d31d7d06b6995`。生产接线为 [control connection](../outputs/df-local-server/dfserver/legacy_ds_control_connection.py:1957) 将 ready Pawn bodies 送给 [movement consume](../outputs/df-local-server/dfserver/legacy_ds_movement.py:82)，再由 runtime 解 field6 并调用 clock epoch/position 接纳策略。不是旧报告的无 reason 版本：现在有封闭 reason code 和计数。

该链保存 raw MoveFlags，却没有按 bit2 更新冲刺意图、运行 Sprint FSM、调用 stamina 请求或创建起止结果。`AcceptedPositionState` 仍是位置/时钟/revision 状态；max_speed 等是明确的本地接纳策略，没有从冲刺配置恢复速度、耗尽阈值或消耗率。传输 receipt/ACK 和 `movement_accepted` 不能证明发生了这些动作。

当前 [vitals producer](../work/portable_map_vitals_probe.py:26) SHA256 `3075ab375f16528113512eead014f641595f8fef18f4e102a934346bb0258e84`：给五个默认组件发送 `build_empty_rep_layout_content()`，没有 health/movement/stamina/skill 值。源码注释也明确这种生产者用途是元数据采样。因此当前没有可声称已闭环的 stamina tick 或 sprint 结果复制。

## 5. 耐力边界与下一条依赖

本轮把真实耐力请求入口缩到 `UGPStaminaDataComponent::RequestStaminaChange` 的正常 native body `0x4575b90`，完整缓存范围 3483B。其身份由原盘唯一同名 literal `0x15e0bcc8` 在 `0x45767d9` 的引用资格化。`0x45f0de0` helper 在 `0x45f2571` 调用该入口，SprintExecuteAction 的 `+0x330` 方法中有对该 helper 的调用分支。

这里仍未恢复此次 Sprint 请求的确切类型/参数、注册与移除的完整语义、配置/模式选行、消耗和恢复 tick、疲劳转换、负重/姿态/伤害/中断规则，以及耐力和起止结果的普通复制 layout。动作构造函数中的浮点默认值尚未资格化为消耗率或阈值，不能拿来填写生产配置。旧冻结 100/100、340/605 等观察值也不能代替本轮实际运行状态或规则。

当前要完成的生产链具体剩下五项：

1. 从输入 `0x4eeb740` 的实际 pressed/released 源值闭合 virtual `+0x480` 的对象、目标和作者 event 映射，包含按住/切换及取消分支。
2. 闭合 saved move flags 返回值到发送端 Params.MoveFlags 的 store，并以一条自然按/放请求的精确 component/field/bit slice 验证。
3. 在已识别 SprintExecuteAction 三个方法和 `RequestStaminaChange` 周围恢复实际参数、资格条件、同局状态提交、疲劳与打断结果。
4. 从权威 stamina 更新与起止提交推导结果复制对象/字段/codec，不能把意图位或传输 ACK 当作成功结果。
5. 在同一 admission/代际的权威角色状态中实现这些动作，并完成运动模拟/纠正。随后再按授权原生试验流程验证自然输入及连续体力时间序列。

`ServerEnterSuperSprint` 是另一个 C->S RPC；本轮没有将它混入普通 Sprint 的授权或成功结果。没有补造 RPC index、enum、Net handle、消耗率或阈值，也没有实现或验收生产冲刺。

## 6. 复核

只读脚本 [research_sprint_flow_20261021.py](../work/research_sprint_flow_20261021.py) 不执行 native 代码。代码查询读固定镜像/缓存并逐块核验；`--verify` 重算所有固定文件、代码和原盘记录。可在本仓库重放：

```bash
python -B work/research_sprint_flow_20261021.py --verify work/evidence/gameplay-sprint-flow-research-20261021.json
```

本轮已执行该命令，exit 0，26 个文件、21 段代码及 6 段原盘记录共 53 项全部匹配。该命令用于来源校验，不是玩法测试。任何后续源码变化都应保留这份固定版本并另行报告漂移；不要把源代码哈希通过改写成原生冲刺验收。

随后独立复核发现协作者更新了 `portable_source_guard.py`、`portable_map_bootstrap.py` 和 `game_server_probe.py`，旧快照的这3个文件已不匹配，21段原生代码与6段原盘记录仍一致。当前代码新增 admission 的 `qualification_scope` 和作用域内来源校验缓存；本文使用的移动收件、意图位和体力实现边界未因此改变。保留原始证据，另存 [当前源码复核快照](../work/evidence/gameplay-sprint-flow-reaudit-20261021.json)，并已对新快照重跑上述 `--verify`，53项全部匹配、exit 0。复核当前文件时将命令的证据参数改为该新文件；原快照仍用于记录旧时点，不能覆盖后宣称旧时点未发生变化。
