# 协作交接

更新日期：2026-09-30。此记录供从 GitHub 接手的开发者和代码代理使用。

## 本次源码快照检查

2026-09-30 将待上传的 Git 索引单独检出，在全新 Python 3.12 虚拟环境按 `requirements-optional.txt` 安装依赖后，执行 `python -m unittest discover -s outputs/df-local-server/tests -t outputs/df-local-server -v`，241 项测试通过（20.459 秒）。源码上传审计通过。此检查未启动原游戏，也不证明尚待复核的客户端交互已修复。

## 已接入的实现

- 本地账号与 SQLite 持久化、原客户端身份提供者、限时 360 秒启动及客户端日志监听。
- 客户端目录驱动的商店展示、枪械预设到真实 receiver 的映射、持久化枪械组件树、购买与出售事务。
- 按已恢复客户端配置提供胸挂和背包的具体格子；保留请求指定的目的位置。
- `CSDepositOperateBulletReq` 的真实装弹/卸弹枚举、弹药兼容关系、已核实弹匣容量、枪内弹药持久化和库存变更通知。
- `CSDepositUpdateBodyContainerReq` 的当前已观察容器同步，包含数量守恒、落位检查、原位置清空和事务回滚。

这些是代码实现范围。模型显示、鼠标卡住、登录状态异常等用户反馈仍需在实机操作中逐项复核；不能据自动测试宣称全部已修好。

## 待修清单

| 工作 | 当前证据与缺口 | 主要代码 |
| --- | --- | --- |
| 枪械与弹药 | 40 棵默认组件树中 31 棵已有核实容量。9 棵对应的旧弹匣函数尚未恢复，未知值不得补猜 | `weapon_ammo.py`、`weapon_ammo_catalog.json`、`extract_weapon_ammo_catalog.py` |
| 新资源对应 | receiver `18050000033` 未在本轮基础武器表找到完整弹药类别，需找实际新表 | `weapon_component_catalog.json`、`scan_weapon_tables.py` |
| 耐久显示 | 甲的最大耐久有来源表。头盔及未知配置仍有历史默认 100，必须继续恢复并替换这些假定值 | `local_commerce.py`、`armor_durability_catalog.json` |
| 商城与交易行 | 商品目录不等于售卖规则；部分 merchant/exchange 关联仍需客户端证明 | `local_commerce.py`、`handshake_diagnostic.py` |
| 近战武器 | 已使用实际 ID `18100000001` 并纳入拥有/装备响应；单独持久化的近战数据仍需核对完整装备与移动流程 | `core.py`、`handshake_diagnostic.py` |
| 容器与购买 | 当前同步只覆盖已观察胸挂、背包和临时区；口袋、安全箱及其他请求需恢复实际行为 | `core.py`、`handshake_diagnostic.py` |
| 临时区清理 | `CSDepositClearCarryOutTempPropsReq` 仍需按客户端调用链恢复，不能无依据删除已付款物品 | `handshake_diagnostic.py`、只读 Lua 解析工具 |
| 历史候选配置 | 地图的 `map_id` 与部分安全屋设施 ID/等级仍是历史候选或外部资料推断，需要客户端核实后替换 | `local_map_board_candidates.json`、`safehouse_max_level_candidates.json` |
| 实机复核 | 登录状态异常、出售、购买后药品落位、模型及退出页面时卡住需要同一轮带日志测试 | `watch_client_log.py`、原客户端受控测试 |
| 中断恢复 | 2026-09-30 最后一轮测试进程中断，SDK 已按哈希恢复；本机观察报告损坏，需要保留损坏文件并修复恢复记录后再次测试 | `recover_interrupted_trial.py`、`verify_local_provider_client.py` |

尚未核实容量的 receiver：`18010000011`、`18010000017`、`18050000005`、`18060000007`、`18060000008`、`18070000002`、`18050000008`、`18020000012`、`18050000033`。

## 分工与提交

1. 领取一个问题，从最新 `main` 建立一个分支；修改前明确负责的模块和接口契约。
2. 并行修改时分开数据提取、业务事务和协议响应；多人需要改 `core.py` 或 `handshake_diagnostic.py` 时先协调，不覆盖彼此的提交。
3. 每个永久映射给出表名、行/函数/偏移、源哈希和提取脚本。记录候选推断与已核实值的区别。
4. 提交业务与协议变更的针对性测试。涉及库存必须验证数量守恒、稳定且唯一的本地 gid、重连保持、失败整批回滚和客户端位置。
5. 完成代码检查后，使用独立 shadow 做 360 秒原客户端测试，全程挂日志，并验证原 SDK 恢复。原始日志、账号、凭据、抓包、游戏资源和编译产物不上传。
6. Pull Request 写清实际变化、来源、运行的测试、实机结论和尚未覆盖的交互；未通过实机复核的部分明确保留为待验。

## 数据与复现

迁移包保留的已提取 JSON 可直接用于开发。新电脑缺少旧 `Saved/Dolphin` 或 `Saved/LuaSource` 缓存，不是继续工作的前置阻碍。重新提取时需为新安装定位实际来源，不能假设旧路径存在。

GitHub 仅存静态目录、字段元数据、描述符及其来源信息；原始 `.uasset/.uexp/.bin`、PAK、Lua 缓存和测试数据库不在仓库。部分只读提取脚本依赖本机证据文件，需先用扫描工具找回相同条目并核对哈希后再运行。
