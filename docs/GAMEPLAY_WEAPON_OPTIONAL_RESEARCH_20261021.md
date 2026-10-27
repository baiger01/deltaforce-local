# 射击可选数据与车辆校验格式补查

日期采用北京时间 2026-10-21。延续[射击协议报告](GAMEPLAY_WEAPON_WIRE_RESEARCH_20261020.md)，本轮收窄 FireInfo 基类、瞄准可选数据和车辆校验三个分支。只读原安装与既有代码缓存，没有访问进程、启动游戏、发包或读写账号。

来源仍是客户端 SHA256 `4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`、代码缓存 manifest `dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。[复核工具](../work/research_weapon_optional_contract_20261021.py)固定验证 11 个原生函数、6 个结构声明和 11 个数据范围；[JSON 证据](../work/evidence/gameplay-weapon-optional-research-20261021.json)保留完整指令、声明、字段偏移和哈希。它复用上一轮工具，另从实际 getter 验证超出旧工具范围的 RigidBodyState 声明。

## 1. FireInfo 基类顺序与子弹数组

实际 `WeaponFireRepInfo` 的 serializer `0x2184ed0` 先调用 `0x2184790`。后者完整 1059 字节，SHA256 `24229c3676477aa9177a69ecdda0bc8ae9bd200c96efc44a4cf37cd255043095`。普通无字节交换 archive 的顺序是：

1. `FireId`：raw64。
2. `BulletIndex` 的零值标记：1 bit；为零标记时省略，否则 raw8。这里与独立 Hit 请求中的 raw64 BulletIndex 是不同结构成员。
3. `InitSpeedFor3P`：uint16；加载乘 100.0，保存乘 float32 约 0.01 后截断。
4. `NewAmmoCount`：raw uint16。
5. `AmmoId` 的零值标记：1 bit；非零再 raw64。
6. `ComboNumber` 的零值标记：1 bit；非零再 raw8。
7. 两个 `Sim3PContinue*Count` 同时为零的标记：1 bit；不同时为零再按顺序写两个 uint16。
8. `OptionalData`，调用 `0x2184bc0`。
9. `BulletInfos` 数量及各元素。

数组数量 helper `0x2181ac0` 完整 768 字节，SHA256 `12fdb6e2b8e1f576f6d81a590956b92f8a14ed944c2ff209e113c9a8efa36aad`。数量是 **raw signed32**，不是反射数组的 uint16，也不是 packed integer。加载负数会改为 0 并置失败标志，超过当前上限会截为上限并置失败标志；元素内存 stride 是 `0x118`，随后逐项调用 `0x2184000`。stride 不是线上元素长度。

`0x2184b3b` 从 `0x1cac9ca8` 读当前上限。静态登记 `0x2a9f40` 中的参数和原盘 UTF16 名称确认其为 `Weapon.Net.MaxBulletArrayNum`；该地址的**原文件初值**为 1000。本轮没有读取当前控制台值，因此 1000 不能直接作为任意会话的永久协议上限。

派生 serializer 的字段顺序已与 UHT 对应：省略/显式 InitSpeed、FireStateFrameNo、FireTimeStamp、FTCT、ClientLogicFireTimeStamp、ServerDeltaTime、ForceMakeDamageOnDS 单 bit、CharacterOwnerLoc、bHeavyAttack 四字节 bool、CustomValue uint8、两个客户端连续开火计数 uint16。声明里的 `VehicleId+0x7c`、`bIsVehicleLeanOut+0x80` 没有在该 serializer 正常路径直接写出，不能按内存字段列表自行插入。

## 2. WeaponFireOptionalData

`0x2184bc0` 完整 770 字节，SHA256 `c52093694bd619b49040794df3e3117e2826822c116de90abba391820c5ce576`。实际顺序：

- `DataOption` 只传 2 bits。0 直接结束；1、2、3 均进入共同部分。
- 共同部分：MovementTimeStamp raw32；CameraLoc 非零标记 1 bit；需要时传量化 CameraLoc；随后依次传 CameraRot、FireAimRot 两个角度对。
- DataOption 大于等于 2 时，再传 CurrentSeed raw32、KickDeltaTime raw32、Kick_TransRandIndex **4 bits**、KickTargetRot 角度对。

未以猜测给 0..3 命名成永久枚举。CameraLoc 省略检查使用三个分量的绝对值和原盘 float32 容差约 `0.0001`；加载省略值时置零。量化位置通过 `SerializeInt(Max=30)` 读 B，然后依次读取范围 `2^(B+2)` 的三个整数，减去 `2^(B+1)`，乘 float32 约 0.01。它与上一轮 HitResult 的 Max=20、比例 1 的位置编码不同。

### 角度格式还取决于真实配置

角度对 helper `0x21852c0` 完整 759 字节，SHA256 `b0da1cd305886e9670b0730a18c7887837501dcc1c9b9f9d02622adde9450b32`。先传 1 bit 存在标记：无值时加载为两个零；有值时依赖控制台配置：

- `Weapon.Optimize.Net.EnableAimOp` 非零：两个 raw float32。
- 该配置为零：两个 uint16；加载逐个乘 `360/65536`，保存有负角调整及实际 SSE 舍入步骤。

这不是根据名字推断。实际 `0x2185323` 检查值地址 `0x1db7ff9c`；静态登记 `0x2a9ed0` 将该地址与完整 UTF16 配置名关联。该地址不在可直接读为原文件数据的范围内，本轮没有采样运行时值。解码器必须使用有来源的会话配置，不能仅凭“优化通常开启”选择一种格式。上述省略与量化说明以正常有限数值输入为界，没有用数学近似替代全部异常浮点/舍入策略。

## 3. 车辆开火校验的展开格式

实际 `DFMVehicleWeaponFireCheckData` serializer `0x52cefd0` 完整 681 字节，SHA256 `8346e935ec2313cfd8a09083f7eb6729d079799ba0197290d1a1b153d01ca114`。它在外层 bHasVehicleWeaponFireCheckData 为真时被调用，内部三个标志并不省略其后的字段。按实际写入顺序：

1. bIsUnderFPP、bIsAutonomousVehicle、bHasVehicleLocation：**各按四字节 bool**。
2. SeatName：archive 的 FName 虚调用。
3. AutonomousFrameData.FrameId：raw32。
4. RigidBodyState.Position：Max30、比例 100 的量化 Vector。
5. RigidBodyState.Quaternion：四个 raw float32，完整函数 `0x1779fa0` 验证，不是三个旋转角。
6. RigidBodyState.LinVel、AngVel：各使用同一 Max30、比例 100 的量化 Vector。
7. RigidBodyState.TimeStamp：raw float32。
8. RigidBodyState.Flags：raw8；AutonomousFrameData.CustomData：raw8。
9. AutonomousFrameData.TimeStamp：raw float32。

两个 TimeStamp 位于不同嵌套结构，均实际传输。RigidBodyState getter `0x132ea360` 指向声明 `0x1d7d9670`，64 字节/16 对齐，六个字段的真实偏移将上面的名字逐项对应；没有把相邻字节误标成时间或标志。

三个位置/速度共用 `0x4d121a0`；其 308 字节加载实现已验证。保存调用 `0x21821c0`，739 字节，包含比例 100、数值检查、范围夹取、SSE 舍入、位宽选择及越界失败标志。SeatName 仍须使用真实 archive/FName 上下文；车辆权限、座位身份和服务器状态是另外的权威检查。

## 4. 收窄结果与复核

已经恢复：FireInfo 基类字段顺序与数组头、OptionalData 各 DataOption 分支、角度格式的具体配置依赖，以及车辆分支的字段展开及其量化入口。

仍需分别闭合：当前 archive/配置、非空 BulletInfos 的完整嵌套分支、FireMovePkg 的移动体、LightFeature 的生产与压缩类型、自然请求参数到精确 EOF 的比较，以及真正的扣弹/命中/伤害和结果复制。这里没有生成一个可在任意局发送的 Fire/Hit 请求，也没有新增本地射击权威执行器。

复核命令：

```text
.venv/Scripts/python.exe -X utf8 -B work/research_weapon_optional_contract_20261021.py --verify-evidence work/evidence/gameplay-weapon-optional-research-20261021.json --compact
```

完整提取与第二次对照均 exit 0，11 个函数、6 个结构、11 个数据范围一致。此验证证明源字节与静态契约可重算，尚未进行实机射击验收。
