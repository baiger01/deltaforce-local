# Rush 首次激活、状态监听与冷却选值的新增证据

本轮仅增加本文件、研究脚本和 [JSON](../work/evidence/gameplay-skill-activation-research-20261021.json)。读取对象为同构建原安装、固定 native-code-cache `1792259162856698600`、旧证据及 peer 提取结果。未启动游戏、读取进程、连接网络、打开数据库或写入原安装与 peer。本轮重新完整线性解码 38 个连续 unwind 范围，固定 9 个有对象类型的虚表绑定、14 个来源 pin；大函数保存完整代码 SHA256、范围和支持结论的指令窗口。范围完整不代表全部语义已经恢复。

## 新增证据

1. **`0x32e4160` 返回 DataSystem。** 该 getter 在 `0x32e41c6` 调 `GetSkillSystem 0x32fe140`，正常返回 `SkillSubsystem +0x370`（`0x32e422a`）；同函数的不可变返回类型文字为 `UGPAbilityDataSystem`。因此 `ActivateState` 的 `0x31d1c74 -> getter -> 0x31d1c87 -> 0x34dc8c0` 属于 DataSystem 分支。把这段称为 charging getter/charging 分支会误认接收对象。`0x34dc8c0` 本身也含 `UGPAbilityDataSystem` 类文字，并通过其 `+0x28` 弱引用查询实际 entity context。

2. **作者的 `BeginSkill` 是 task 名，监听参数为独立的 byte 1。** Rush task0 的真实参数仍为 `[self,"BeginSkill",1]`，来源 UEXP `14915` / uber memory offset `6779`。`QA_AbilityListnerState 0x7d41f10` 把 FName 写 task `+0x228`、byte 写 `+0x230`；之后以全局 SkillEntityID `-1` 调 `0x7f1f340`。全局路径选 template `+0x700`，正实体 ID 路径选 entity context `+0x1f0`，再由 `0x7f21880` 以状态 byte 登记实际 task ordinal。`BeginSkill` 字符串不能当作 native enum 1 的文字声明。

3. **状态监听到实际任务的接收边已固定。** DFMAbilityDataSystem 实际构造 `0x7d5e080` 安装 vtable `0x16cd4d20`，其 virtual `0x2a0=0x7d74b40`。该函数检验 entity context，解析 context `+0x18` 的真实 template，调用 `TriggerBehaviorCall 0x7f38260`。后者按 byte 查询 template `+0x700` / entity `+0x1f0`；存在实体覆盖时优先用实体条目，并另处理 template `+0x750` 表。命中条目的 task ordinal 通过实际 template 的 virtual `0x6c8` 分派。

   template 构造 `0x808f380` 在 `0x808f3a5` 取 vtable `0x16f32bf8` 并安装；不可变槽 `0x16f332c0` 绑定 `+0x6c8=0x7ed1cc0`（EnterLogic）。EnterLogic 先 `0x7ed8600` 按实际 task ordinal 查询 task，正常段 `0x7ed1f46 -> DoTrigger 0x7d3b820`、`0x7ed1fbb -> StartEnterLogic 0x7d54470`，继而进入已知 `0x7d05f20/0x7d062d0` 的 policy/override 和 task virtual `0x300/0x308` 路径。task 不存在或 context 无效仍有明确失败路径，不能按任意整数执行。

4. **首次激活发出的普通 command0 也已接到实际 DataSystem，但走另一张表。** `SendFSMEvent 0x32dccc0` 的 authority 段 `0x32dd629..641` 更新旧/当前 FSM skill ID 后调用 `0x3417c40`。有效 enter 分支 `0x3419d94` 调 `OnSkillFSMEnter 0x33a0550`；其 authority 段 `0x33a2a5c` 调 `MarkEnterFSM 0x3323320`，后续正常分支经 `0x3495890 -> SkillState OnEnter 0x33510c0`。`0x3355a31` 明确置 `edx=0`，`0x3355a3a` 调 `0x3315ec0`。

   `0x3315ec0` 从 `0x32e4160` 取得 DataSystem，`0x3316d25` 调其 virtual `0x2b8`。实际 vtable 的目标是 `0x3560c00`；该函数在 `0x3560d0e` 调 context `+0x18` template 的 virtual `0x6e0`，实际绑定 `0x7f38f10`（TriggerSkillBehavior）。这条路径查询 template `+0x660` / entity `+0x1a0` 的 SkillBehaviorMap，以及另一张 `+0x6b0` 表；它也可经 template `+0x6c8` 进入任务，却没有证明命中 `+0x700` 的 BeginSkill 监听器。

5. **field36 与上述两条入口分别有自己的对象和槽。** field36 使用 SkillSubsystem `vtable0x167f7b08 +0x6c0=0x34e4ca0`，然后 DataSystem `+0x2a8=0x7d82990 -> TriggerLogic 0x7f389a0`。状态监听使用 DataSystem `+0x2a0` 和 template `+0x6c8`；普通 command 使用 DataSystem `+0x2b8` 和 template `+0x6e0`。不能把不同接收对象上的槽号合并成一次首次激活链。

## 冷却 `-1.0` 的实际分支

Rush task10 仍是实际 `QA_AbilityCD("RushCD",-1.0)`，作者 override 为 `ServerAndClient1P`。已知运行函数 `0x7cb4630` 调 `0x34cf1c0(slot,-1,float)`；后者取得实际 slot record，再经 `StartCountDown 0x355e320` 转 `0x351c0a0`。本轮完整核对了后两层及相关 getter。

- `0x351c28d..290` 以 **传入时间是否大于 0** 分流。`-1.0` 属于非正分支，选 `0x34f86f0` 的结果，不会形成负一秒倒计时。该 getter 正常返回 slot record `+0x11c`；当其 `+0x190` owner 弱引用有效且 `+0x14` 非零时，先调 `0x34f8380` 再乘 `+0x11c`。因此原表 Time 还可能受运行时倍率影响。
- 非正分支若旧执行记录有效、旧状态 byte `+0xc=1`、扣减前后 `Num+AmmoNum` 总和变化，且 `0x351cf00` 判定旧 timer 尚未完成，`0x351c30d` 会改用 `0x34f6340` 计算的剩余时间。它按实际时钟模式计算并 clamp 到 0。不能固定解释为每次重置完整 20 秒。
- 随后，旧记录有效且活动、时间相同、timer 未完成、数量总和未变时，`0x351c3bd..3c0` 跳过新倒计时记录。**这只是 timer 记录的复用条件。** `0x351c1ef` 的数量修改发生在它之前：传入整数 `-1` 先取反为消费请求 1，再走 `0x34e1e80`。因此该复用分支不能证明重复 task 不会再次扣数量。
- 真正新建时，`0x351c3fc -> 0x34c34f0` 取得记录，写 duration `+0x14`、`end +0x20=duration+clock`、`delay +0x1c=end-selected_duration`、选中 duration `+0x10`，最后 `0x351c48f -> 0x3554420` 提交。传入正值还另有 min 与特定 0.1 秒兜底分支，不能套用到非正分支。

这推进了哨兵的数值语义，但本局 mode/submode/map/tag 的最终选行、运行时倍率、首次 DataSystem 状态分支与 RushCD task 的资格/重复关系仍未全部闭合。本轮没有宣布当前有效 CD=20 秒或“一次激活必然只扣一次”。

## 结论与精确未闭项

已闭合：作者 listener 的真实登记布局、状态消费后的 task 接收边、template 构造与槽绑定、普通 command0 到 DataSystem 和 SkillBehaviorMap 的独立路线，以及非正 CD 的选值、旧 timer 复用条件和数量修改顺序。

仍未闭合的最后连接是：**首次 `OnSkillFSMEnter/MarkEnterFSM` 状态提交，如何产生/入队/消费 listener byte 1，并在同一对象关系下到达 DataSystem `ConsumeCommand_BS 0x7d74b40`。** 当前证据没有判断它是同步额外事件还是后续消费/tick，也没有用普通 command0 的另表路线替代它。每个 Rush task 的完整运行 policy、异步 callback 时间及异常/取消事务继续受旧报告边界限制。任务接收者已经存在且已定位，本轮未将问题退回“receiver 不存在”。

## 重放

原 EXE SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`，固定 cache manifest SHA256 `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。重放重新读取同一实际作者包、不可变 PE、固定缓存、对象虚表槽及函数连续范围，前后重哈希来源。

```bash
.venv/Scripts/python.exe -B work/research_skill_activation_20261021.py --verify work/evidence/gameplay-skill-activation-research-20261021.json
```

`--verify` 不写文件；`--output` 仅接受本仓库 `work/evidence` 中尚不存在的文件。重放匹配仅证明静态材料和派生证据可复核，不证明原生运行或完整释放生产实现已经完成。
