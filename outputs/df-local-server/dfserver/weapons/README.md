# 枪械、配件、弹药、近战与插槽

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [weapon_ammo.py](weapon_ammo.py)：提供真实配置中的枪弹兼容关系与弹匣容量。
- [weapon_assembly.py](weapon_assembly.py)：按账号已拥有的物品实例保存枪械配件树与装配变化。
- [weapon_components.py](weapon_components.py)：从已提取的预设节点表提供枪械默认配件。
- [melee_weapons.py](melee_weapons.py)：提供本地账号装备所用的真实近战武器与皮肤映射。
- [socket_guid.py](socket_guid.py)：按已采集的原生规则解码配件插槽GUID。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
