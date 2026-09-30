# deltaforce-local

更新日期：2026-10-01。本页记录已完成内容，作为协作和代码审查的进度基准。

## 分工

| 负责方 | 负责范围 |
| --- | --- |
| 本会话 Codex | 枪械、配件、弹药、近战武器，以及药品、防具、背包、胸挂等杂货；对应的商店购买、出售、仓库、装备和持久化逻辑 |
| 另一位协作者 | 地图、战局及相关协议和状态流程 |

## 实机已确认

| 内容 | 已完成结果 | 验证 |
| --- | --- | --- |
| 本地大厅接入 | 通过本地账号及自建身份提供者直接启动独立 shadow，连接本机服务并进入原客户端大厅 | 原客户端运行记录、用户操作 |
| 防具与容器购买 | 单条护甲、头盔报价改用客户端实际读取的档位；护甲、头盔、背包、胸挂均可购买 | 2026-09-30 用户实测确认；同轮护甲、头盔成交及存档记录 |
| 子弹与药品重开 | 购买后退出再进入，两页购买选项均正常；原客户端连续购弹与药品请求成功 | 2026-09-30 用户实测确认、同轮客户端及服务日志 |
| 出售接口 | 两次原客户端测试出售请求成功，服务执行物品删除与货币更新 | 原客户端请求及服务记录 |
| 近战武器 | 近战选择页与装备栏的名称、模型及切换正常；所选刀具持久化 | 2026-09-30 用户实测确认；18:09 原客户端装备请求成功及 SQLite 重读 |
| 枪械皮肤 | 本地账号提供普通枪械皮肤，列表与装备可用 | 2026-09-30 用户实测确认“皮肤没问题”；客户端真实皮肤目录与装备持久化用例 |
| 曼德尔十连与购买 | 十连动画、奖励页和购买均正常；八次连续十连记录 80 件奖励与扫描历史 | 2026-10-01 用户实测确认；00:51 至 00:55 原客户端八次扫描成功及动画结束回调、SQLite 重读 |
| 测试工具 | 360 秒限时启动、客户端日志监听及原 SDK 哈希校验与恢复工具已运行使用 | 本机测试记录 |

## 代码与数据已完成

下表记录已实现且有目录或自动测试依据的内容。

| 内容 | 已完成范围 | 对照文件 |
| --- | --- | --- |
| 本地账号 | 注册、密码登录、会话撤销、SQLite 存档与账号隔离 | `dfserver/core.py`、`tests/test_accounts.py` |
| 客户端物品目录 | 物品、仓库格子、干员外观、护甲耐久和错误码的提取结果及来源信息已入库 | `protocol/*_catalog.json`、[数据来源](DATA_PROVENANCE.md) |
| 枪械配置 | 恢复 40 套默认枪械组件树、预设到真实 receiver 的映射，组件以稳定本地 gid 保存 | `weapon_component_catalog.json`、`weapon_preset_catalog.json`、`dfserver/weapon_components.py` |
| 弹药关联 | 恢复 261 条武器配置、176 条弹药配置，核实 31 套默认枪械的弹匣容量 | `weapon_ammo_catalog.json`、`dfserver/weapon_ammo.py` |
| 装弹与卸弹 | 接入真实装卸弹枚举、口径匹配、容量检查、枪内弹药保存、库存变更响应与通知 | `dfserver/core.py`、`dfserver/handshake_diagnostic.py`、`tests/test_native_inventory.py` |
| 背包与胸挂 | 恢复 44 项具体容器布局，按客户端配置提供分区格子 | `container_layout_catalog.json`、`dfserver/container_layouts.py` |
| 容器同步 | 接入已观察的胸挂、背包和口袋同步；实现落位检查、堆叠拆分、数量守恒及失败整批回滚 | `dfserver/core.py`、`tests/test_local_commerce.py`、`tests/test_native_inventory.py` |
| 口袋与重连购买 | 按真实口袋位置支持物品移入；重连购买补发库存变更通知，购买 137 发、装入 17 发、同步口袋及重读存档的回归用例已通过 | `dfserver/core.py`、`dfserver/handshake_diagnostic.py`、`tests/test_local_commerce.py` |
| 商品时间判断 | 按客户端时钟用法将心跳时间改为 Unix 秒；购买前后商品详情的开放时间与心跳时间兼容的回归用例已通过 | `dfserver/handshake_diagnostic.py`、`tests/test_local_commerce.py`、[数据来源](DATA_PROVENANCE.md) |
| 单条防具报价 | 类型目录与商品详情使用客户端 `GetPropSaleInfo` 的档位 0 回退规则，保留满耐久比例 | `dfserver/local_commerce.py`、`tests/test_local_commerce.py`、[数据来源](DATA_PROVENANCE.md) |
| 购买与出售事务 | 实现扣款、物品持久化、指定位置、堆叠上限、出售删除与货币变更 | `dfserver/local_commerce.py`、`dfserver/core.py`、`tests/test_local_commerce.py` |
| 近战数据与装备 | 从客户端条目 7276 恢复 18 组刀具 receiver/外观对应，本地提供原客户端确认解锁的 15 组；迁移误用的喷枪记录，下发匹配的收藏与装备数据，保存所选刀具，切换使用装备删除/加入响应 | `melee_weapon_catalog.json`、`dfserver/melee_weapons.py`、`tests/test_melee_inventory.py` |
| 枪械皮肤数据 | 恢复 1776 条真实外观与武器、预设关系，本地提供 1514 条开放的普通外观；按归属和枪种校验装备，保存单枪及同枪种默认设置，保留组件和枪内弹药 | `gun_skin_catalog.json`、`dfserver/gun_skins.py`、`tests/test_native_cosmetics.py` |
| 曼德尔目录与购买 | 恢复 34 种砖与奖池、11 项商城关系、5 项经验卡赠送密钥配置；实现整批报价校验、扣款与收藏入账，迁移旧密钥货币记录并防止重复迁移 | `mandel_box_catalog.json`、`dfserver/mandel.py`、`tests/test_native_cosmetics.py` |
| 本地扫描事务与协议 | 实现砖和密钥扣除、真实皮肤实例、历史与计数持久化；收藏通知先于购买回调，十连动画响应只含十件奖励。抽样使用明确记录的本地规则 | `dfserver/mandel.py`、`dfserver/handshake_diagnostic.py`、`tests/test_native_cosmetics.py`、[规则与来源](DATA_PROVENANCE.md) |
| 商城配置提取 | 恢复 158 条推荐、61 条特供、8 个干员研究奖池的 64 条奖励、54 条外观归属及原生主页签；保留原始行、偏移与来源哈希 | `premium_shop_catalog.json`、`work/extract_premium_shop_catalog.py`、[数据来源](DATA_PROVENANCE.md) |
| 原生商城接口 | 接入推荐、特供、购买记录、研究奖池及干员外观装备；按配方、原价和已拥有内容核价，扣费、发货与记录整笔提交；周限购累计，旧轮次拒绝重复执行；收藏及干员归属通知先于购买回调 | `dfserver/premium_shop.py`、`dfserver/handshake_diagnostic.py`、`tests/test_premium_shop.py` |
| 推荐页宣传跳转 | 接回 16 条原生奖池宣传项及客户端跳转目标，包含安魂 `10210005 -> 20300008`；空配方宣传项不能作为商品购买 | `premium_shop_catalog.json`、`dfserver/premium_shop.py`、`tests/test_premium_shop.py` |

表内 `dfserver/`、`tests/`、`protocol/` 均位于 `outputs/df-local-server/`。

## 已完成验证

- 2026-09-30：单独检出上传源码，在全新 Python 3.12 环境安装依赖，全部 241 项自动测试通过。
- 2026-09-30：口袋与重连购买修正后，本机源码全部 243 项自动测试通过。
- 2026-09-30：心跳时间修正后，全部 244 项自动测试通过（20.256 秒）。
- 2026-09-30：单条防具报价修正后，全部 244 项自动测试通过（19.966 秒）；360 秒原客户端试验完整结束，原 SDK 恢复并通过哈希校验。
- 2026-09-30：近战修正后全部 248 项自动测试通过；17:57 原客户端确认 15 条可见刀具外观已解锁，18:09 装备请求成功，所选 receiver `18100000014` 重读一致，用户确认名称、模型及切换正常。两轮 360 秒试验完整结束，原 SDK 恢复并通过哈希校验。
- 2026-09-30：枪械皮肤与曼德尔购买、扫描事务接入后全部 264 项自动测试通过（104.085 秒）；新增用例复现并修正购买通知顺序与十连返回十二件展示物品的问题，检查重连入口实际发送的加密包、保存重读与失败回滚。
- 2026-10-01：原客户端连续八次十连成功，每次保存十件奖励；包含核心奖励展示流程，八次均记录动画结束回调，本轮未出现 Fatal error。用户确认十连与购买正常；360 秒试验完整结束，原 SDK 恢复。
- 2026-10-01：再次启动的 360 秒试验记录三次成功的枪械皮肤装备请求，结束后原 SDK 恢复。日志监听输出改用 UTF-8，GBK 环境下特殊字符不中断捕获的独立回归测试通过；本轮完整日志补读完成，未出现 Fatal error。
- 2026-10-01：商城修复后全部 284 项自动测试通过（27.974 秒），包括 18 项商城用例和底层协议校验的内存回归。原客户端研究奖池空请求、指定奖池查询及三个整包赠品领取请求成功；特供礼包购买响应成功。第三轮 360 秒试验完整结束，配置、购买记录及奖池请求均收到响应，日志未出现 Fatal error 或崩溃堆栈；原 SDK 与游戏源文件哈希一致。
- GitHub 仓库已按用户指示改为公开，源码、测试、静态目录和来源信息已上传；上传文件审计通过。

## 协作依据

提交与审查对照本页：新增成果说明改了哪些文件、来源是什么、通过了哪些测试，以及哪些操作得到实机确认。涉及共享文件时先协调责任范围。客户端 ID、枚举、配置和关联信息必须先查客户端并记录依据，规范见 [AGENTS.md](AGENTS.md)。运行命令见 [运行说明](docs/RUNNING.md)。
