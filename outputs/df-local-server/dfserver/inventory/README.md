# 库存、容器、仓库、安全箱与卡包

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [container_layouts.py](container_layouts.py)：提供从真实客户端配置提取的胸挂、背包等容器尺寸。
- [deposit_sort.py](deposit_sort.py)：为原客户端仓库整理请求执行明确的本地装箱策略。
- [native_keycards.py](native_keycards.py)：加载真实门卡配置，并校验门卡与卡包布局关系。
- [native_keychains.py](native_keychains.py)：依据真实门卡和卡包表管理账号权限与门卡放置。
- [native_prop_bindings.py](native_prop_bindings.py)：持久保存原生物品实例的显式PropInfo绑定。
- [native_warehouse_extensions.py](native_warehouse_extensions.py)：处理仓库扩展箱、已获得格子及普通空箱操作。
- [native_warehouse_growth.py](native_warehouse_growth.py)：管理已核实的仓库容量、扩展登记及旧存档容量保留。
- [native_warehouse_wire.py](native_warehouse_wire.py)：在库存业务响应中保留原客户端缓存的仓库扩展计数。
- [safe_boxes.py](safe_boxes.py)：提供已核实的安全箱方形布局及明确的本地测试权限。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
