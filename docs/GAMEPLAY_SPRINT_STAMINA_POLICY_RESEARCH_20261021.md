# SprintPenalty 注册输入与负重曲线键

本轮仅收窄两个已定位输入：重复启动阈值的确切 global pointer `0x1ddefc30`，以及前轮 BP 默认组件真实引用的 `OverloadStaminaChangeCurve`。旧六份研究文件保持固定，新建 [policy helper](../work/research_sprint_stamina_policy_20261021.py)、[独立证据](../work/evidence/gameplay-sprint-stamina-policy-20261021.json) 和本报告。没有修改生产源码、README、协作者文件或原安装；没有访问进程、启动游戏、访问网络/数据库、操作 shared shadow、执行配置或调用 gameplay 原生方法。本轮曲线原存储没有压缩，也没有调用 Oodle codec。

## 1. 阈值 pointer 的静态注册来源

只查询确切 pointer 的 RIP 引用与赋值，先从 `0x1ddefc30` 的 MOV load/store 现场定位到注册函数 `0x36da80`。117B 完整缓存范围 SHA256 为 `ed5ad73567a3e59996c9b307b536dd64335f2c39639d137c0ab6ea4e97ad9b34`。

该函数的实际参数和 store 链为：

```text
0x36da9f: r9   = UTF-16 literal "ConsecutiveSprintPenalty Duration Time"
0x36daa6: xmm2 = float32 [RVA 0x14ec8340] = bits 0x3f800000 = 1.0
0x36daae: rdx  = UTF-16 literal "Sprint.ConsecutiveSprintPenaltyDuration"
0x36dab5: stack argument +0x20 = 0
0x36dabd: call manager virtual +0x10
0x36dac7: [global 0x1ddefc28] = returned object
0x36dadb: call returned object virtual +0x60
0x36dae5: [global 0x1ddefc30] = returned data pointer
```

两个字符串在原盘 `0x15e09df0/0x15e09e40`；默认 float 原盘字节是 `00 00 80 3f`。这里是明确的注册默认值，未从动作构造浮点推测。原盘 `0x14d422e8` 还存在指向 `0x36da80` 的函数指针记录；本轮未扩大恢复整个静态初始化调度器。

已确认消费者 `0x45f24d8` 读取同一 global pointer，`0x45f250b` 从 `[pointer+r15*4]` 取 float，r15 是当前分支计算的 0/1 索引。随后 `0x45f252d/0x45f2535/0x45f253d` 将转换后的 world `+0x610` double 时间差与其比较，并用 `comiss/jae` 分派计数递增或重置。world 字段单位本轮没有独立资格化，因此这里只报告默认 float `1.0`，不追加单位推断。

## 2. 启用项是另一项输入

从调用者对相邻确切 pointer `0x1ddefc18` 的读取追到注册函数 `0x36da10`，112B SHA256 `081483ca421bdfddced1e24dc530138d0704cc98e8a34f19e5882bfaa267e507`：

```text
0x36da2f: r9  = "Enable ConsecutiveSprintPenalty"
0x36da36: r8d = 0
0x36da41: rdx = "Sprint.ConsecutiveSprintPenalty"
0x36da48: call manager virtual +0x20
0x36da52: [global 0x1ddefc10] = returned object
0x36da66: call returned object virtual +0x50
0x36da70: [global 0x1ddefc18] = returned data pointer
```

name/help 在原盘 `0x15e09db0/0x15e09d70`；原盘 `0x14d422e0` 有函数指针 `0x36da10`。消费者 `0x45f0e4e` 取该 data pointer，`0x45f0e7c` 比较所选字节是否为零，为零时 `0x45f0e80` 直接跳出 helper。因此存在 SprintPenalty 配置行和请求代码不能证明当前惩罚已启用；注册默认参数是 0，当前有效值及运行时覆盖来源未观察。

`0x14b4e590` 的清理路径使用已注册对象 `0x1ddefc28`，不是耐力动作生命周期的注册/移除证明。两个运行态 data pointer 不在本轮可读取的原盘 file-backed 数据范围，不能从原 EXE 直接读取当前槽值。

证据中的确切 RIP 查询固定 4 个已资格化结果：threshold store `0x36dae5`、load `0x45f24d8`，以及 enable store `0x36da70`、load `0x45f0e4e`。候选来自冻结代码中 REX+MOV load/store/LEA 的 RIP-disp32 形式，逐项通过真实函数边界重解码；这是明确语法范围内的结果，未将其当作全指令集的不存在证明。

## 3. 沿真实组件引用恢复曲线键

前轮确认的组件 `OverloadStaminaChangeCurve` ObjectProperty，`.uexp` tag `77618`、value `77643`、import=-268，真实路径是 `/Game/BluePrints/GameModes/TestGame/Curve/OverloadStaminaChangeCurve.OverloadStaminaChangeCurve`。本轮只匹配该完整 package 的 `.uasset/.uexp`，重新验证当前 257 个 PAK 的 primary/secondary index；精确资产对唯一命中 `pak-0-1-pakchunk30-WindowsClient.pak`。

原 PAK `.uasset` entry offset `1323008`，decoded size `809`，无压缩、加密；`.uexp` entry offset `1323877`，decoded size `258`，无压缩、未加密。两者的原始存储 SHA1 校验通过，解码内容、哈希和原字节范围在 JSON 内保存，无另外写入资产文件。

package 只有一个 `CurveFloat` root export，name `OverloadStaminaChangeCurve`，export record offset `689`、payload offset `0`、size `254`。其 `FloatCurve` 是 `RichCurve`，内含 `Keys` 和 `Orders`；`Keys` 的内层 tag 明确是 `RichCurveKey`，value offset `135`、size `54`，严格容纳两个 27B 序列化键，`Orders=[0,1]`。

序列化顺序由固定的本地 UAssetAPI `FRichCurveKey` reader 第 37–47 行交叉核对：三个模式 byte 后依次是六个 float32。原盘 UHT `0x1d813390 -> property list 0x1b5eaf90` 独立固定了 `RichCurveKey` 的字段名、native offset 及 native sizeof=28B；没有将带 padding 的 native struct 直接当作 27B 线格式。

- 键 0，`.uexp` offset `135`：`Time=0.0`，`Value=1.30385160446167e-08`，Value 原位值 `0x32600000`。
- 键 1，`.uexp` offset `162`：`Time=1.0`，`Value=1.0`，两者位值均为 `0x3f800000`。
- 两键 `InterpMode` byte 均为 0；原盘 enum getter `0x133c63c0 -> 0x133c6980 -> descriptor 0x1d812958` 的实际 name/value 表 `0x1b5ea8c0` 将 0 绑定为 `RCIM_Linear`。
- 两键的 TangentMode/TangentWeightMode byte 和四个 tangent float 均为 0，原 27B 字节逐键保存。第一键没有近似写成零。

这里的 `Time` 是曲线键字段名。调用者送入曲线的值如何由负重状态计算、归一化和裁剪，以及曲线输出在完整耐力公式中的使用，均未在本轮恢复；不能把横轴 0..1 擅自命名为某种体重比例，也未执行曲线求值。

## 4. 收窄后的依赖与复核

本轮闭合了重复启动阈值和启用项的静态注册身份、默认参数及 data pointer 生成/消费边，也恢复了组件所指曲线的真实键。剩余规则输入是实际会话的 console 有效值/覆盖来源，以及原生曲线输入换算、动态属性倍率和消费资格；这些仍需分别资格化。本轮不扩大声称恢复完整疲劳系统、权威事务、结果复制或原生玩法验收。

```bash
PYTHONUTF8=1 ./.venv/Scripts/python.exe -B work/research_sprint_stamina_policy_20261021.py --verify work/evidence/gameplay-sprint-stamina-policy-20261021.json
```

本轮实跑 exit 0，1081 项全部匹配：25 份来源、9 段代码、11 段原盘记录、1034 段 PAK 字节，以及曲线重新解析和 PAK inventory 各一项。旧六文件各自哈希也包含在来源验证中。复核不启动游戏、不调用 console 注册或 curve 求值方法；`--emit-evidence <新文件>` 可重放确切 RIP 查询和完整精确资产取证，并拒绝覆盖已有文件。
