# SOL Pawn 默认组件中的 Sprint 体力配置

本轮从已确认的 `BP_DFMCharacter` 资产及 `GPStaminaDataComp` 对象引用出发，恢复其默认组件内两张配置 map 的实际序列化值。旧 [体力调用研究](GAMEPLAY_SPRINT_STAMINA_RESEARCH_20261021.md)、helper 和证据保持固定；本轮仅新增本报告、[配置 helper](../work/research_sprint_stamina_config_20261021.py) 和 [独立配置证据](../work/evidence/gameplay-sprint-stamina-config-20261021.json)。未修改生产源码、README、协作者文件或原安装。

研究只读原盘和既有提取文件；没有进程访问、游戏启动、网络或数据库访问、shared shadow 操作，也没有运行游戏配置或调用 gameplay 原生方法。仅使用已安装的纯 Oodle 压缩 codec 在内存中重解两个已定位资产；codec 的 PE 依赖与文件哈希均记录。没有导出解密材料或复制 codec。

## 1. 具体入口及原盘来源

入口来自既有 `native-owning-weapon-cooked-character-emptyhand-defaults.json` 的实际导出、导入和引用，未按相似资产名猜选配置。

资产是 `/Game/BluePrints/Characters/BP_DFMCharacter`。重新解析其 package 表得到：

- export 46：`BP_DFMCharacter_C`，class 为 `BlueprintGeneratedClass`，super 为 `/Script/SOL.SOLCharacter`。
- export 47：`Default__BP_DFMCharacter_C`，class_index=46，template 为 `/Script/SOL.Default__SOLCharacter`。
- CDO 的 `GPStaminaDataComp` ObjectProperty 位于 `.uexp` tag `34960`、value `34985`，真实 int32 引用是 export 119。
- export 119：`Default__BP_DFMCharacter_C.GPStaminaData`，class `/Script/GPGameplay.GPStaminaDataComponent`，outer=47，template `/Script/SOL.Default__SOLCharacter.GPStaminaData`。`.uasset` export record offset `131213`；`.uexp` export offset `75502`、size `2198`。

本轮重新枚举当前 `Content/Paks/*.pak` 的 257 个文件，验证每个 primary 和 secondary index 的 SHA1，仅匹配上述完整 package 路径的 `.uasset/.uexp`。两者都唯一命中 `pak-0-1-pakchunk30-WindowsClient.pak`：物理 entry offset 分别为 `600064` 和 `640873`。随后重读压缩块、验证压缩源 SHA1、在内存重解并与既有提取文件逐字节比较，二者相同。

`.uasset` 为 141301B，SHA256 `e3271f94f8105e60bc3ced6509ba9c7d38cc15429b9bb7a032f43d4cdadca6ed`；`.uexp` 为 96051B，SHA256 `fec5a2317e3fbf1ac69d5526b89347b2aaec0f2ce8c00043e945069f7f502144`。证据固定 18 份来源文件和 1032 段原安装 PAK 字节范围，并保存当前 PAK inventory、索引校验和精确命中结果。该包在此 inventory 内没有同路径重复项；其他运行时覆盖机制仍未资格化。

## 2. 两张配置表的实际行

以下 offset 均为 `.uexp` 文件 offset，不能直接当作 native component member offset。

`StaminaIndependentChangeConfig` 的 tag 起点 `75531`、value 起点 `75572`、end `77344`。序列化 header 为 removed_count=0、row_count=14；全部 14 行按原 NameMap、EnumProperty key 与 StructProperty 字段严格解析，末尾恰好等于该 tag 的 end。

目标行 `EStaminaIndependentChangeType::EStaminaIndependentChange_SprintPenalty` 的 key offset 为 `77092`，整行结束 `77218`，四个字段全部显式序列化：

- `bIsInstant=true`，BoolProperty tag `77100`；bool 字节在 tag `+24`。
- `InstantValue=-1.0`，FloatProperty value offset `77151`。
- `DurationValue=0.0`，FloatProperty value offset `77180`。
- `bCanTriggerUnderLowStamina=true`，BoolProperty tag `77184`。

`StaminaExclusiveChangeConfig` 的 tag 起点 `77344`、value 起点 `77385`、end `77618`。header 为 removed_count=0、row_count=5，五行均只有显式 `DurationValue`，也严格消耗至 tag end：

- Sprint：key `77438`，`DurationValue=-3.0`，float offset `77471`。
- SuperSprint：key `77483`，`DurationValue=-20.0`，float offset `77516`。
- SwimmingSprint：key `77528`，`DurationValue=-5.0`，float offset `77561`。
- StandRun：key `77393`，`DurationValue=4.5`，float offset `77426`。
- Normal：key `77573`，`DurationValue=4.5`，float offset `77606`。

完整枚举名称、每行/每字段的 tag 类型、offset 与原字节 SHA256 都保存在 JSON，未以 JSON 浮点重新编码代替原序列化证据。与前轮原生 UHT 类型对应：independent 的 native map 为组件 `+0x118`、value 类型 16B `FStaminaIndependentChangeInfo`；exclusive 为组件 `+0x168`、value 类型 4B `FStaminaExclusiveChangeInfo`。

组件还显式序列化 `StaminaRecoverStartCD=1.5`，FloatProperty tag `75502`、float offset `75527`。这是该 BP 默认组件的实际配置，不能用 native 构造中的浮点默认值代替它。

## 3. 与原生调用契约合并后的边界

前轮已固定 `0x45f2571 -> RequestStaminaChange` 的 `type=0x12 SprintPenalty`、`DeltaSeconds=0` 和 `ChangeCount=min(counter+1,13)-3` 条件分支。现在该 BP 行显式 `bIsInstant=true`、`InstantValue=-1`，因此此分支的配置基础变更为 `-ChangeCount`，随后仍受 `StaminaIndependentNegativeChangeRate`、资格门槛、上下界和提交路径影响。不能仅凭此配置推导自然按键触发次数或最终耐力结果。

常规持续 Sprint 是独立路径：`tick 0x45c5d10 -> UpdateStamina 0x45fd770`，类型 1 分支读取 exclusive 的 `DurationValue`，再乘 `StaminaSprintChangeRate`。本轮为该 BP 找到的系数是 `-3`，所以该已恢复分支的配置基础项为 `delta * (-3) * 当前 StaminaSprintChangeRate`。这不等于已验证所有状态下固定每秒减 3；运行时属性、覆盖、负重/buff、恢复、其他贡献项及完整状态选型仍未闭合。

恢复计时的生成/消费边也获得具体默认配置：负变更将 `StaminaRecoverStartCD +0x110` 复制到 `+0x1ec` 并将 `+0x1ea` 置 false，tick 减 delta 后在不大于零时置 true；此 BP 序列化等待值为 `1.5`。本轮没有执行该状态机或观察实际恢复时序。

## 4. 下一条具体依赖

本轮取得了此前缺失的两张 map 来源行，剩余配置依赖更具体：

- `StaminaSprintChangeRate` 和独立变更倍率的实际初始化/动态修改，以及当前模式或 hotfix 的运行时覆盖。包内默认值已确认，不能将倍率默认为 1。
- `SprintPenalty` 重复启动时间阈值仍来自原生全局指针 `0x1ddefc30`，其有效值与控制变量来源未恢复。
- 该组件 `OverloadStaminaChangeCurve` ObjectProperty 明确引用 `/Game/BluePrints/GameModes/TestGame/Curve/OverloadStaminaChangeCurve.OverloadStaminaChangeCurve`，tag `77618`、value `77643`、import=-268。该路径来自真实组件引用，可作为后续负重消费研究入口；本轮未提取或解释曲线。
- 完整资格/疲劳/打断门槛、任何实际注册/移除契约、权威提交与结果复制仍按前轮列明的依赖继续恢复。这里没有生产实现或原生玩法验收。

## 5. 复核

```bash
PYTHONUTF8=1 ./.venv/Scripts/python.exe -B work/research_sprint_stamina_config_20261021.py --verify work/evidence/gameplay-sprint-stamina-config-20261021.json
```

本轮实跑 exit 0，共 1052 项全匹配：18 份来源文件、1032 段 PAK 原字节、当前 inventory 和重新解析配置各一项。该复核检查原始来源和解析输出；不启动游戏，也不重调压缩 codec。`--emit-evidence <新文件>` 可重新执行完整原盘索引与两个精确资产的解压比较，拒绝覆盖已有文件。
