# Actor、NetGUID、复制字段与序列化

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [legacy_ds_actor_bunch.py](legacy_ds_actor_bunch.py)：组合NetGUID导出、普通Actor创建头和显式内容块。
- [legacy_ds_actor_content.py](legacy_ds_actor_content.py)：处理受限的Actor选择器内容块并保留未解释的复制正文。
- [legacy_ds_actor_fields.py](legacy_ds_actor_fields.py)：按类网络缓存字段索引封装Actor内容字段。
- [legacy_ds_actor_manifest.py](legacy_ds_actor_manifest.py)：预检显式描述且不含属性的初始Actor创建计划。
- [legacy_ds_actor_open.py](legacy_ds_actor_open.py)：编码已恢复的普通引用SerializeNewActor字段。
- [legacy_ds_class_net_cache.py](legacy_ds_class_net_cache.py)：读取并校验离线类网络缓存快照中的字段布局。
- [legacy_ds_game_spawn_flags.py](legacy_ds_game_spawn_flags.py)：按当前客户端写入规则计算Actor生成标志位。
- [legacy_ds_guid_exports.py](legacy_ds_guid_exports.py)：处理已恢复的普通分支NetGUID导出格式。
- [legacy_ds_quantized_vector.py](legacy_ds_quantized_vector.py)：编码已恢复的出生位置压缩向量。
- [legacy_ds_scalar_serializers.py](legacy_ds_scalar_serializers.py)：依据已核实的原生属性规则编码标量值。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
