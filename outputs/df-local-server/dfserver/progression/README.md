# 任务、声望、设施、通行证与赛季

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [battle_pass.py](battle_pass.py)：处理真实通行证配置的查询、解锁与领奖事务。
- [native_action_progress.py](native_action_progress.py)：按真实赛季等级表管理独立于账号经验的行动经验与等级。
- [native_department_queries.py](native_department_queries.py)：提供部门信息查询及累计声望计算。
- [native_departments.py](native_departments.py)：按真实部门映射保存和更新部门奖励余额。
- [native_quest_abandon.py](native_quest_abandon.py)：处理已接受的普通SOL任务放弃及状态更新。
- [native_quest_conditions.py](native_quest_conditions.py)：根据账号货币、等级等实际状态评估已接任务条件。
- [native_quest_rewards.py](native_quest_rewards.py)：在同一事务中发放任务奖励，并保存来源行去重凭证。
- [native_quest_wallet.py](native_quest_wallet.py)：在钱包事务提交后刷新已接任务的现金目标。
- [native_quests.py](native_quests.py)：处理真实任务的接受、提交与本地进度持久化。
- [native_safehouse.py](native_safehouse.py)：处理设施生产的材料扣除、计时和产物领取。
- [native_safehouse_progress.py](native_safehouse_progress.py)：处理设施建造升级的费用、材料提交与持久化计时。
- [native_season.py](native_season.py)：为大厅段位和赛季界面提供已恢复的赛季元数据。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
