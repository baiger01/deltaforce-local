# deltaforce-local

更新日期：2026-09-30。本页记录已完成内容，作为协作和代码审查的进度基准。

## 分工

| 负责方 | 负责范围 |
| --- | --- |
| 本会话 Codex | 枪械、配件、弹药、近战武器，以及药品、防具、背包、胸挂等杂货；对应的商店购买、出售、仓库、装备和持久化逻辑 |
| 另一位协作者 | 地图、战局及相关协议和状态流程 |

## 实机已确认

| 内容 | 已完成结果 | 验证 |
| --- | --- | --- |
| 本地大厅接入 | 通过本地账号及自建身份提供者直接启动独立 shadow，连接本机服务并进入原客户端大厅 | 原客户端运行记录、用户操作 |
| 护甲购买 | 本地客户端已成功购买护甲 | 用户实测确认 |
| 出售接口 | 两次原客户端测试出售请求成功，服务执行物品删除与货币更新 | 原客户端请求及服务记录 |
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
| 购买与出售事务 | 实现扣款、物品持久化、指定位置、堆叠上限、出售删除与货币变更 | `dfserver/local_commerce.py`、`dfserver/core.py`、`tests/test_local_commerce.py` |
| 近战数据 | 使用客户端实际模板 `18100000001`，纳入本地拥有及装备响应 | `dfserver/core.py`、`dfserver/handshake_diagnostic.py` |

表内 `dfserver/`、`tests/`、`protocol/` 均位于 `outputs/df-local-server/`。

## 已完成验证

- 2026-09-30：单独检出上传源码，在全新 Python 3.12 环境安装依赖，全部 241 项自动测试通过。
- 2026-09-30：口袋与重连购买修正后，本机源码全部 243 项自动测试通过。
- GitHub 私有仓库已建立，源码、测试、静态目录和来源信息已上传；上传文件审计通过。

## 协作依据

提交与审查对照本页：新增成果说明改了哪些文件、来源是什么、通过了哪些测试，以及哪些操作得到实机确认。涉及共享文件时先协调责任范围。客户端 ID、枚举、配置和关联信息必须先查客户端并记录依据，规范见 [AGENTS.md](AGENTS.md)。运行命令见 [运行说明](docs/RUNNING.md)。
