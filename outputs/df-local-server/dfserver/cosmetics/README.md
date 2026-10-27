# 干员、枪械、账户外观与收藏

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [gun_skins.py](gun_skins.py)：管理本地账号的真实枪械皮肤归属和装备状态。
- [hero_customization.py](hero_customization.py)：管理真实干员外观目录、账号归属及各模式的保存选择。
- [profile_cosmetics.py](profile_cosmetics.py)：保存账号头像等资料外观的拥有与选用状态。
- [weapon_pendants.py](weapon_pendants.py)：处理武器挂饰收藏，并独立保存皮肤与挂饰装备状态。
- [native_collection.py](native_collection.py)：按真实收藏加载回调处理已读回执和账号红点状态。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
