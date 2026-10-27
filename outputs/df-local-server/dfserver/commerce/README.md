# 交易、商城礼包与曼德尔扫描

本目录是实际实现。根包同名文件是旧路径兼容入口。

- [local_commerce.py](local_commerce.py)：处理本地原客户端试验的商品库存、购买与物品状态投影。
- [premium_shop.py](premium_shop.py)：依据真实商城配置和本地存档处理礼包查询、购买及奖励发放。
- [mandel.py](mandel.py)：提供曼德尔物品、扫描奖池映射及本地抽奖事务。

资源位置统一读取 `dfserver._paths`；修改后运行服务根目录的测试。总览见[结构说明](../../../../docs/architecture/SERVER_LAYOUT.md)。
