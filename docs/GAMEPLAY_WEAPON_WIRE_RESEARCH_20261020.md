# 射击协议与原生处理链补查

2026-10-20，只读原安装PE声明和同版本代码缓存。客户端SHA256为`4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0`，缓存manifest为`dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754`。没有进程访问、游戏启动、发包或账号读写。

复现工具：[research_weapon_wire_contract_20261020.py](../work/research_weapon_wire_contract_20261020.py)。分步查询及其SHA256集中在[验证索引](../work/evidence/weapon-wire-research-20261020/verification.json)。代码范围与声明包含跨查询重复项，不能把次数当成独立函数数量。部分早期查询使用了工具的前一版本，索引明确保留这一事实；最终复核读取全部记录并重新验证原始字节。

10:29:07 UTC复核20份查询中的42段代码、135段不可变记录全部匹配；当前查询/验证工具AST通过。没有使用数据库或发送测试请求。

## 1. 请求声明与真正的处理入口

[声明与exec](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-rpc-implementations-20261020.json)重新从原盘验证：

- Fire getter是`0x60fa140`，FunctionParams `0x1cd6b050`，SHA256 `33488ef936ab124645633f1e731051d0904f7ee2a1ef630c25f1adafe55766c5`。唯一参数FireEventParam，struct getter`0x60f9170`，flags`0x80280cc0`，native params608字节。
- Hit getter是`0x60fa1a0`，FunctionParams `0x1cd6b0a0`，SHA256 `67266232937c5542e68c1053d4018bc2ce92053f8ca8fe3a47d61c9e059fcba8`。唯一参数BulletHitInfo，struct getter`0x218f2d0`，flags`0x280cc0`，native params208字节。
- 两种表不能按相邻指针猜配对：UHT链接是getter/name，native注册表是name/exec。以名称匹配和实际FunctionParams为最终依据；此前战斗报告中的`0x60f9170/0x218f2d0`是参数struct getter，不是上述RPC getter。
- Fire exec`0x6101d90`先正常构造参数，从VM参数栈读取后调用虚槽`+0x738`验证，true才调用`+0x740`。false走实际验证失败处理。Hit exec`0x6101e70`取参后调用虚槽`+0x730`。这证明解码与处理是两层，不能以收到参数代替执行成功。

[DFM构造函数与虚槽](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-authority-vslots-20261020.json)从实际`0xc732f00`的`0xc732f25 mov [rbx],rax`确认primary vtable是`0x17db5808`；`0x16ee9150`是对象`+0x388`的接口表，不能混用。对应`+730/+738/+740`的真实目标分别是`0x58f29d0 / 0x58f2750 / 0xc7c2d10`。

这些目标的[连续函数体](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-authority-handlers-20261020.json)均存在。DFM Fire handler在`0xc7c2d7e`调用基类`0x58f1cc0`，并有自己的后续分支；不是空返回stub。基类[2696字节函数](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-base-fire-20261020.json)SHA256 `a4e52ee0a7c4658e26df42590e4374598d4723ad067af3f915871d5166b2adce`，包含实际技能武器/模式阶段限制、fire movement处理及下游组件调用。日志字串只能辅助定位；每个分支的完整业务含义、动态组件类型和当前实例虚表仍须分别资格化，不能仅凭这些名字给本地请求返回成功。

## 2. 两个结构确实走自定义序列化

[原始结构声明](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-uht-20261020.json)给出WeaponFireEventParam608字节、BulletHitInfo208字节、RequestPointHitActionParam856字节的内存字段。[CppOps工厂](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-cppops-20261020.json)与[操作表](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-ops-tables-20261020.json)确认：

- FireEventParam ops`0x1682f5f8`：`+60 -> 0xd5c5d0`返回true，`+70 -> 0x60fc910 -> 0x58cfff0`。
- BulletHitInfo ops`0x15909320`：`+60`同样true，`+70 -> 0x218dad0 -> 0x2183b70`。
- RequestPointHitActionParam ops`0x165adbf8`的`+60/+70`均为false stub。不能把三个同属“命中/开火”的结构统一按同一种布局发送。

标志设置的决定性通用构造证据见[技能报告第11节](GAMEPLAY_CHARACTER_RESEARCH_20261020.md:224)：PrepareCppStructOps根据`+60`设置StructFlags的`0x400`，实际布局构建器再选择native NetSerialize。`+70`是serializer入口，单看该槽不能替代标志选择证明。

## 3. FireEventParam的实际线序

[serializer `0x58cfff0`](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-custom-serializers-20261020.json)完整678字节，SHA256 `72c0279377c8355868c1474988cf7b93a7c3ef3d476b8e0e84f49dc5bc5f6345`。正常archive下按以下顺序调用，且不等于UHT数组或608字节memcpy：

1. EventType：raw uint8。
2. FireInfo：实际对象vtable`+8`的自定义serializer。
3. LightFeatureType：raw uint8。
4. LightFeatureStr：调用`0x109ea340`。
5. LightFeatureRawData：调用`0x10b7230`。
6. LightFeatureUnCompressSize：raw32；TimeStamp：raw float32。
7. FireMovePkg：调用`0x4d115e0`。
8. bHasVehicleWeaponFireCheckData：**按4字节整数化bool**序列化；非零再调用`0x52cefd0`。加载且为零时初始化该结构默认值。

[参数构造](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-fire-object-20261020.json)进一步确认`0x58765c0`把FireInfo实际vtable设为`0x158f7d80`，其`+8`是`0x2184ed0`，不是凭类型名称猜函数。该[888字节函数](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-leaf-serializers-20261020.json)先调用基类`0x2184790`，后有InitSpeed相等省略位、frame/timestamp、ForceMakeDamageOnDS单bit、CharacterOwnerLoc三float32、bHeavyAttack四字节bool、CustomValue uint8及两个uint16连续开火计数。

[GPFireMovePkg](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-nested-serializers-20261020.json)同样先序列化四字节bValid，true才进入`0x4d11810`的实际移动包serializer。不能把这个bool或Fire的车辆bool改成普通反射bool1，也不能把NewServerMove某一限定分支直接代替完整FireMovePkg。

LightFeature的[可变长leaf补查](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-quantization-and-variable-leaves-20261020.json)也已有实际函数体：`0x109ea340`先读signed32长度，正数走单字节序列，负数取反后按UTF16单位读取，拒绝INT_MIN并检查archive长度限制；`0x10b7230`先读raw signed32元素数，再读连续byte，负数及条件性上限失败置archive错误。这里是自定义serializer里的数组，不能套用医疗通用反射数组的uint16计数。

本节已经定位实际执行序列与嵌套函数，尚未将所有FireInfo基类可选分支、FireMove和车辆分支全部实现为可发送codec。LightFeature压缩类型、声明解压尺寸、对象与实际实例资格不能补默认假值。

## 4. BulletHitInfo的实际线序

[serializer `0x2183b70`](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-custom-serializers-20261020.json)完整239字节，SHA256 `92f6f4f4058502be85b4c68e6eed16214dbe98c597c3ed2e0a4c681d95598109`。顺序是BulletIndex raw64、SpawnLocation三raw float32、TimeStamp raw float32，最后进入继承结构BulletHitRepInfo的`0x2183c60`，不是先序列化base再追加三个字段。

[base serializer](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-nested-serializers-20261020.json)637字节，SHA256 `4374d643c31ac54469538654299bc6cc2d6ad7ecdd6a5ae1f85a986c4b911fe7`：

- BulletGuid raw64；AmmoIdIsZero单bit，false才序列化AmmoId raw64。
- HitResult调用`0x126d92b0`。失败立即返回，不能继续当合法命中。
- InitSpeedFor3P按uint16存储：保存先乘原盘float32约0.01再截断，加载乘100.0。这两个值已重读原盘`0x14f345b4 / 0x14ec8390`确认，不能按原float32字段直接写32bits。
- bAfterRPCOpt单bit；为1时再写bHitLandScape和bHitCharacterMesh两个bit，为0清两项。
- bClientHitStaticSceneObject单bit；为1再写bClientHitStaticSceneLandScape，为0清后一项。

[FHitResult `0x126d92b0`](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-leaf-serializers-20261020.json)987字节，SHA256 `8bdf6696f2067481242bef64cf723337d9e846d663e4fe903b61e5fa25cd56f8`。其header是7bits，含blocking/start-penetrating和位置/法向相等、FaceIndex/Item=-1、PenetrationDepth=0的省略标记；后续调用量化位置`0x2183ee0`、法向`0x126d9690`，包含真实物理材质/Actor/Component引用和FName。**SpawnLocation的普通Vector与HitResult内部量化Vector是不同编码。**

两个量化leaf的加载分支也已[读取完整函数](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-quantization-and-variable-leaves-20261020.json)：位置先SerializeInt(Max=20)得B，再依次SerializeInt(Max=2^(B+2))得三个分量，逐个减bias=2^(B+1)，转float32；不能把bounded-int当packed GUID或一律5bit长度。法向每分量SerializeInt(Max=65536)，减32768再乘原盘float32常量`0x14f34588`；[常量记录](../work/evidence/weapon-wire-research-20261020/gameplay-weapon-normal-scale-20261020.json)值约`0.000030518509447574615`。保存方向另走量化函数，当前没有把所有范围/舍入/非法输入策略实现为codec。PackageMap与FName仍需要实际archive、映射及版本上下文，不能把对象地址或名称字符串直接放进去。

## 5. 研究推进与实施边界

本轮已从“结构有字段”推进到真实serializer、动态对象构造、RPC exec和DFM/base实现。下一步可以沿上述确定入口逐个恢复剩余leaf并做离线边界测试；不是重新搜索Fire/Hit名称。

仍不得宣称完整开火/命中成功：当前Python生产收件器尚没有该射击权威执行器；必须将真实owner/武器、服务器位置和时钟、弹药、射击序号、目标/遮挡、伤害及结果复制接入同一局事务。专用serializer成功或客户端自报DamageResult不能代替服务端判定。当前独立证据仍缺本次自然Fire/Hit参数slice到精确EOF的比较、全部可选分支以及射击/伤害/扣弹/重试/结算的原生操作验收。

重新验证只读证据：

```powershell
& .\.venv\Scripts\python.exe -B work/research_weapon_wire_contract_20261020.py --verify-saved work/evidence/weapon-wire-research-20261020
```
