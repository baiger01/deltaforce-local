# Sprint 体力请求与持续更新的新增原生边

本轮只读原安装 EXE、同构建冻结 native-code-cache `1792259162856698600` 和协作者研究文件。没有访问进程、启动游戏、执行原生方法、操作 shared shadow、发包、访问数据库或修改协作者文件。结论是原生源码契约的进一步收窄，未实现或验收生产奔跑。

镜像 SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`，manifest SHA256 `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。本轮 [独立证据](../work/evidence/gameplay-sprint-stamina-research-20261021.json) 固定 9 份来源文件、27 段原生代码和 35 段原盘记录，并保留指令、unwind 范围、代码哈希及结构化结论。原 Sprint flow 与 reaudit 两份证据均未覆盖。

## 1. SprintPenalty 请求的真实参数

沿用既有研究恢复的 `SprintExecuteAction` getter `0xce8aa50`、构造 `0xce8bb70`、primary vtable `0x186b1e70` 身份；本轮重新核对原盘 slots `+0x330/+0x338/+0x340` 为 `0xab8a250/0xac85270/0xabfdbb0`，以及三个方法的完整缓存范围。`+0x330` 中 `0xab8c755..0xab8cc0a` 从动作 `+0xc8` 取黑板，再解析黑板的加密 `+0x1c8` Sprint 指针；其中 `0xab8c780/0xab8caea/0xab8cb3a/0xab8cc0a` 调用同一 helper `0x45f0de0`，它们对应指针包装器的不同路径，不是四次独立业务请求。

helper 的 `0x45f24c3` 要求 `Sprint+0x120` 非空；原盘 UHT `0x16785480` 将该成员命名为 `StaminaData`，native offset 为 `0x120`。`0x45f2561..0x45f2571` 的实际调用参数为：

```text
rcx  = [Sprint + 0x120]
dl   = 0x12
xmm2 = 0.0
r9d  = updated_counter - 3
call 0x4575b90
```

UHT params `0x1cd4e590` 的属性列表 `0x16787688` 及记录 `0x16787628/0x16787600/0x167875d8` 分别命名参数为 `StaminaChangeType`、`DeltaSeconds`、`ChangeCount`，native params offset 为 `0/4/8`。exec `0x6090750` 在 `0x6090820/0828/082e` 从解析后的参数取出 `r9d/xmm2/edx`，于 `0x609083e` 调用上述 body。body 在 `0x4575bc3/5bcb/5bcf` 保存 `xmm2/dl/r9d`，调用约定与消费两侧吻合。

类型值不是根据顺序猜测：enum getter `0x5fc62b0 -> 0x5fc7a20` 使用 descriptor `0x1cd06b30`，它指向 19 项 name/value 表 `0x1665cde0`。末项 `0x1665cf00` 为字符串指针 `0x1665d4a0` 和整数 `0x12`；字符串是 `EStaminaIndependentChangeType::EStaminaIndependentChange_SprintPenalty`。

计数规则也在调用现场：`0x45f251e` 读取 world `+0x610` 的 double 并转成 float，`0x45f252d` 减 Sprint `+0x140` 的上次值，与从全局指针 `0x1ddefc30` 取出的动态阈值比较。差值小于阈值时，`0x45f253f..0x45f2554` 将 `+0x144` 计数递增并以有符号比较限制到 13；只有更新后的计数大于 3 才请求 `ChangeCount=计数-3`。另一分支 `0x45f2578` 将计数重置为 1，两分支都在 `0x45f2582` 保存当前 float 时间。阈值实际值、控制变量身份和模式覆盖没有恢复。

因此这条新边是重复启动的 `SprintPenalty` 请求。它的 `DeltaSeconds=0` 不能当作普通奔跑的每秒体力消耗参数。

## 2. 独立请求配置及变更提交

原盘 UHT `0x16784640` 将组件 native `+0x118` 命名为 `StaminaIndependentChangeConfig`；同名 value property `0x167846c8` 的 struct getter 是 `0x608e490`，它读取 descriptor `0x1cd4e130`。类型 getter `0x608ef10` 明确给出 `StaminaIndependentChangeInfo` 与 16B。descriptor 的四属性列表 `0x167871e0` 绑定：

- `bIsInstant +0`：UHT `0x167871a8` 的 setter `0xd903b0` 精确执行 `[rcx]=1`。
- `InstantValue +4`：UHT `0x16787180`。
- `DurationValue +8`：UHT `0x16787158`。
- `bCanTriggerUnderLowStamina +0xc`：UHT `0x16787120` 的 setter `0xec25e0` 精确执行 `[rcx+0xc]=1`。

`RequestStaminaChange` 在 `0x45765ba..0x4576648` 按请求类型查询这张表，缺行或属性对象 `component+0x1e0` 为空时退出。记录 stride 为 `0x1c`，value 从 record `+4` 开始；不是将 16B value 的布局当作整个 map pair。`0x4576660..0x457667b` 的两分支为：

```text
bIsInstant != 0: float(ChangeCount) * InstantValue
bIsInstant == 0: DeltaSeconds * DurationValue
```

负变更再读取属性对象 `+0x168`，仅其当前值大于 0 时乘上该值。原盘 UHT `0x1661c1c0` 将此属性绑定为 `StaminaIndependentNegativeChangeRate`。正变更有另一个 `+0x178` 分支，本轮没有独立命名它。通用属性 reader `0x2fe60a0` 的正常 body 从属性数据 `+0xc` 返回 float。

`0x45766e4..0x457674d` 读取当前 Stamina、MaxStamina 和组件 `StaminaLowerLimit`，按上下界生成候选；当与旧值差异超过原盘容差后，用 descriptor helper `0x39e5a80` 取得 `GPAttributeSetSpeed.Stamina`，再将候选放入 `xmm2` 传给 `0x2fe73d0`。原盘 UHT `0x1661c2b0/0x1661c280/0x16784720` 分别固定属性 `Stamina +0x118`、`MaxStamina +0x128` 和组件 `StaminaLowerLimit +0x10c`。本轮没有恢复 `0x2fe73d0` 下游完整提交、回调及复制事务。

`0x4576752..0x4576765` 在负变更时，将组件 `StaminaRecoverStartCD +0x110` 复制到 `+0x1ec`，并将 `+0x1ea` 置 false。该字段名由 UHT `0x167846f8` 资格化。这给后述 tick 的恢复计时提供了新增生成端。

## 3. 常规持续更新的独立路径

tick 接收者身份已闭合：`GPStaminaDataComponent` class getter `0x608db70` 指向 constructor thunk `0x608e8b0`，thunk 取 initializer 的对象后跳转 `0x449dd20`。构造在 `0x449dd58..0x449dd5f` 写 primary vtable `0x15e0b608`；原盘 `0x15e0b940` 即 slot `+0x338`，值为 `0x45c5d10`。该方法同时引用 `UGPStaminaDataComponent` 和 `FActorComponentTickFunction`，在 `0x45c5e1c` 更新属性绑定后，于 `0x45c5e29` 调用 `UpdateStamina 0x45fd770`，将本次 tick 的 `xmm1` 原值继续作为 delta 参数。

`UpdateStamina` 正常 body 的 `0x45fd7a8` 保存 delta；其身份另由 `0x46064ad/0x4606539` 对原盘 `UGPStaminaDataComponent::UpdateStamina` 的引用和 native exec `0x6091580 -> 0x45fd770` 核对。

这条持续更新使用另一张表。UHT `0x16784588` 将组件 `+0x168` 命名为 `StaminaExclusiveChangeConfig`，同名 value property `0x16784610 -> 0x608e460 -> descriptor 0x1cd4e0e0`；类型 getter `0x608eeb0` 明确是 `StaminaExclusiveChangeInfo`、4B，仅有 `DurationValue +0`（UHT `0x16787090`）。它与上一节 16B 的 independent value 是不同类型。

exclusive enum getter `0x5fc6270 -> 0x5fc79f0 -> descriptor 0x1cd06af8` 的实际 5 项表 `0x1665cc10` 固定 Normal=0、Sprint=1、StandRun=2、SuperSprint=3、SwimmingSprint=4。`0x46010c1` 读取从 owner 黑板 `+0x1c8` 解出的 Sprint `bSprinting +0x102`；这与动作在 `0xab8b99e/0xabff2e1` 写 1/0 的字段吻合。经先前门槛后，`0x4603359..0x460336d` 的一条分支按 Sprint `bSuperSprinting +0x101` 选择 1 或 3。两个 bool 字段的 UHT `0x167855e0/0x16785618` 与 setter `0x31838c0/0x603fbd0` 也重新核对。

`0x46063c2..0x4606447` 按所选 enum 查询组件 `+0x168`，pair stride `0x10`、value offset `+4`；缺行不会进入本段消耗。`0x4606450` 先算 `delta * DurationValue`，类型 1 分支 `0x4606460..0x4606474` 再读取属性 `+0x148`，于 `0x46065dc..0x46065e1` 乘 `StaminaSprintChangeRate`。该属性身份由 UHT `0x1661c220` 固定。这里恢复了乘法契约，没有恢复实际模式配置行的数值或符号，也没有把 SuperSprint 分支自动套用同一公式。

随后 `0x4606609..0x46066a6` 的候选分支将持续变更与另一贡献值合并，经 `StaminaLowerLimit/MaxStamina` 约束后用相同 Stamina descriptor 传给 `0x2fe73d0`。另一贡献值及全部恢复分支未恢复，不能将本段写成完整体力公式。tick 的 `0x45c5e2e..0x45c5e54` 还在 `+0x1ea` 为 false 时从 `+0x1ec` 减 delta，并在余额不大于 0 时置 true；与上一节负变更重置计时构成具体的新生成/消费边。

## 4. 精确剩余项

- 找到当前模式实际组件配置行：independent key `SprintPenalty=0x12` 的 `bIsInstant/InstantValue/DurationValue`，exclusive `Sprint=1/SuperSprint=3` 的 `DurationValue`，以及资产覆盖和动态倍率来源。组件构造清空两张 map，构造默认浮点不能代替这些行。
- 资格化 `0x1ddefc30` 对应的重复启动阈值及有效模式值；完整追 `UpdateStamina` 中 `0x1cbd17da/0x1cbd17d9` 等门槛、后续状态选型、恢复、负重、buff、疲劳和中断。
- 继续恢复动作生命周期与任何实际注册/移除契约。本轮看到的大量指针解码、重编码和 wrapper 刷新不是体力注册/移除证明；没有新增完整注册/移除结论。
- 闭合 `0x2fe73d0` 下游权威提交及结果复制，再以同 admission 的自然按/放与连续体力序列验证。缓存范围完整、回调存在和以上静态边均不等于生产玩法验收。

## 5. 复核

[只读 helper](../work/research_sprint_stamina_20261021.py) 用固定 helper 哈希、manifest 和原盘 PE/unwind 表读取冻结代码；支持 `--function`、`--span`、`--window`、`--record` 和调用/literal 查询。源码验真命令为：

```bash
PYTHONUTF8=1 ./.venv/Scripts/python.exe -B work/research_sprint_stamina_20261021.py --verify work/evidence/gameplay-sprint-stamina-research-20261021.json
```

本轮执行结果：exit 0，9 份来源、27 段代码和 35 段原盘记录共 71 项全部匹配。校验包含原 EXE 全文件 SHA256。这是来源复核，不是原生执行或功能测试。`--emit-evidence <新文件>` 在无额外目标参数时可重放本轮固定范围，并拒绝覆盖已有文件。
