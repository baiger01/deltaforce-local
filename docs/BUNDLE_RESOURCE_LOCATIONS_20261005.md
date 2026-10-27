# 商城礼包资源位置

2026-10-05 逐项核对全部 158 条推荐、61 条特供，共 219 行、1325 个资源字段槽。完整清单保留每行原 ID、字段编号、原始引用与源表偏移；没有用礼包名称猜路径。

## 已完成补齐

48 条推荐含已确认用途的 CDN 图片，共 189 个不同目标。原有 49 个缓存保留，两轮新增 140 个、104,514,651 字节；当前 189 个均有缓存，全部通过完整图片解码或原版有界解压，新文件重读长度和哈希一致。再次生成计划为 0 网络请求、0 新增、0 已知目标缺缓存。

原始清单记录的是补齐前的缓存快照。当前状态以[最终执行报告](../outputs/df-local-server/protocol/premium_shop_cache_repair.json)为准：187 个保留包含首轮新增的 138 个，另两张在重试中新建。10 个只有未知字段 304 用途的目标仍保留原引用，未自动写入。

## 存放位置

下表目录均相对于游戏根目录；补图写入的是独立 shadow。

| 资源 | 实际位置或原始定位信息 |
| --- | --- |
| 推荐大图、小图、Logo 的 CDN 缓存 | `DeltaForce/Saved/Cdn/G/CN/Resource/Store/C=<有符号十进制 CRC>`；逐项原地址和缓存文件名在最终执行报告的 `targets` 中 |
| 原版 CDN 源 | 同版本配置的 `https://cdn.df.qq.com/G/CN/`；无扩展名原路径插入 `/7/`，带扩展名原路径保留。此次修复明确选择默认 CDN；运行客户端的 PC 配置仍为 `https://repo.df.qq.com` |
| 客户端本地图、Logo、特供横幅 | [完整资源清单](../outputs/df-local-server/protocol/premium_shop_resources.json)的 `local_big`、`local_small`、`local_logo`、特供资源字段，保留精确 `/Game/...` 虚拟对象与包路径，共 497 个不同包路径 |
| 本地图的物理包目录 | `DeltaForce/Content/Paks/` 与本机挂载的 Dolphin 热更新 PAK；已核对全部 257 个基础 PAK，但加密目录索引中的具体图片包归属尚未解析，不能把虚拟路径当作已找到的独立文件 |
| 关联视频 | 已找到的 13 个 `.bin` 位于 `DeltaForce/Content/Commerical/CharAppear/`、`DeltaForce/Content/Commerical/WeaponAppear/`、`DeltaForce/Content/Movies_HD/Collection/`；原拼写 `Commerical` 保留。完整清单的 `related_media_resources` 记录每个具体文件与源表大小 |
| 礼包场景背景 | 完整清单的 `related_theme_backgrounds` 记录 96 条精确物品 ID 交集与原场景路径；礼包实际选择该背景的消费字段尚未核实 |
| 奖励枪皮、物品图标、干员模型 | [奖励资源清单](../outputs/df-local-server/protocol/premium_shop_reward_resources.json)保留每个真实奖励 ID 的对应关系：110 条枪皮图片文件名、11 条干员外观的 54 个网格路径、3 个非空物品图标。枪皮仅有文件名的字段未猜补目录 |

源表来自 `pak-0-0-pakchunk2-WindowsClient.pak`：推荐条目 7142、特供条目 7156。原字段与解码 SHA-256、原生路径与 CRC 依据见[数据来源](../DATA_PROVENANCE.md)和[原生图片契约](../outputs/df-local-server/protocol/premium_shop_native_resource_contract.json)。

## 复用工具

安装 `outputs/df-local-server/requirements-optional.txt` 中的依赖后，在项目根目录先生成计划：

```powershell
python work/repair_bundle_cdn_cache.py --game-root "<源游戏目录>" --shadow-root "<独立 shadow 目录>" --branch default --output work/evidence/bundle-cache-plan.json
```

执行缺缓存补齐：

```powershell
python work/repair_bundle_cdn_cache.py --game-root "<源游戏目录>" --shadow-root "<独立 shadow 目录>" --branch default --execute --output work/evidence/bundle-cache-result.json
```

每次输出使用未存在的文件名。工具只创建缺缓存，校验同版本源程序、固定源清单、原生契约和公开缓存控制记录，保留已有文件及完整原始字节。两张带尾部数据的原版 PNG 仅接受已核实的精确路径、长度、哈希、尺寸和 PNG 流结束位置；其他图片校验不因这两项例外放宽。

## 验证边界

相关工具执行 177 项回归，173 项通过，4 项 Windows 符号链接权限测试跳过。当前已知用途缓存均已验证，全部礼包在原客户端中的纹理加载与画面显示仍未逐项验证。02:03 的 1800 秒原客户端试验完整结束，原 SDK 已恢复且与源安装哈希一致。

03:52～03:53 的用户截图确认大量推荐缩略图仍为空白，白鹰军团大图保留了上一项画面。开放推荐中的 92 条没有 CDN 大图／小图，原客户端从本地表读取这些纹理；因此上面的 189 个缓存目标只覆盖有对应 CDN 字段的推荐，不能作为全部缺图已修复的依据。本地图片路径校验、异步加载及实际资源挂载仍在核查。

原客户端实际选用的推荐表为 `/Game/R13N/Common/Base/DataTables/StoreHotRecommendation.StoreHotRecommendation`。11:54 的只读核对先验证 `UDataTable.RowStruct` 类型、对象登记及稳定性，再按真实 TabId 唯一选中白鹰军团、先驱者、秘银工艺、趣味贴纸。四项的大图、小图和 Logo 共 12 个完整路径与基础条目 7142 一致，8 个视频字段均为空。导出的行序号不是原生行名，读取工具按 TabId 选择，不用行序号推算映射。其余推荐的实际行字段未在这次四项读取中验证。

这四项原图的精确对象位于 `/Game/BluePrints/UI/UMG/System/Store_Commercial/<主题>/Texture/`，主题目录分别为 `Whiteeagle`、`xianquzhe`、`MithrilCraft`、`FunyDecal`。最后一项的小图／大图对象名为 `BannerEnter_Scar_FunyDecal`／`BannerBg_Scar_FunyDecal`，不能按礼包名改写。完整对象路径仍见资源清单。这次确认的是客户端使用的虚拟引用，未确认纹理所在的物理 PAK 条目或实际渲染。

源安装与 shadow 的全部 257 个基础 PAK 为相同硬链接文件，28 个 Dolphin 热更新包均记录挂载成功。11:55 对上述 12 个路径的原生缓存哈希链查询均未找到 `BluePrints` 子键；缓存未命中后客户端仍会查询虚拟文件系统，因此该结果不是资源不存在或路径校验失败的证明。11:17 的 1800 秒试验已完整结束，SDK 恢复后的哈希与源安装一致；实际礼包购买请求序号 709 返回 0，并发送收藏变更通知。

12:16 再次查询同一组路径，首次未命中的节点变为 `UI`，12 项仍未取得终端文件名。两次缓存快照不能证明客户端的最终路径校验结果。已取得原版 `LongPackageNameToFilename` 包装及其完整转换函数，代码通过匹配根目录、拼接相对路径和扩展名生成文件名；根目录的实际文字与对应 PAK 条目仍未取得，未据此改写图片路径。

17:57 的只读检查已取得五项实际目录文字，完整报告 SHA-256 为 `a2a9de116a5a4e54c7b5543ca77d0b4e083106faebd56f961350d0bc6d18ef9f`：第一根为 `/Game/`，对应前缀 `../../../DeltaForce/Content/`；第二根为 `/Engine/`，对应前缀 `../../../Engine/Content/`；校验扩展名为 `.uasset`。读取前核对完整转换函数、getter、字符 accessor 的代码哈希和原指令，仅读五个有界 UTF-16 字符串并重读确认稳定。具体 PAK 条目与原生 `FileExists` 结果仍未取得，这次结果不证明图片已显示。

18:10 的只读检查沿原文件查询调用读取固定状态槽、当前接收者首个指针及虚表偏移 `0x78` 的唯一目标，再重读三项确认稳定；目标是原程序 RVA `0x124677e0`。18:15 读取其原 `.pdata` 对应的 46 字节代码段，确认一次直接调用和失败时的后续代码分支。该段不是完整逻辑函数，不能将记录中的旧 `function_complete` 标志作为控制流闭合依据；工具和说明已更正，原始记录保留。仍未观察文件查询返回值或实际纹理加载成功。

23:24 的只读查询取得目录索引的稳定状态：313 条候选包记录，257 条待处理记录均已处理，无额外未索引记录。上述四个原始目录各有 1、1、2、2 条桶候选记录，查询后逐项重读索引字段一致。查询只沿这四个目录的哈希桶和源代码指定的排序键位置读取，没有遍历资源包对象或调用原生函数。完整报告 SHA-256 为 `9b0976f207983a90331250e4f88eaa1f3b75a355abd16e66960b3d5f65d0e133`。桶可能有哈希碰撞，候选记录不等于具体纹理条目；物理 PAK 文件名、包内条目、`FileExists` 返回值和渲染仍未验证。

目录哈希来自同一客户端的实际代码：取文件名最后一个分隔符之前的目录，仅将 ASCII 大写转小写，处理不含终止符的 UTF-16LE 字节。初值 `0x100000001b3`，每字节异或后乘 `0xcbf29ce484222325`，保留 64 位；分桶取结果低 16 位并与原索引掩码相与。没有以通用哈希库替代客户端实现。哈希函数本身是两个相邻 `.pdata` 记录之间的短叶函数，不能把前一个函数的展开记录算作它的函数范围。

22:10 的试验运行 1801.14 秒后按测试上限关闭，SDK 恢复、剩余测试进程为空。该轮没有实际礼包购买请求，记录中的商城数值返回均为 0，因此不能用于验证此前的购买报错已经消失。22:49、23:19 两轮分别在 702.44、652.70 秒提前正常退出（退出码 0），测试器未请求关闭，SDK 已恢复；这些退出不能认定为崩溃，也没有完成 30 分钟观察。

11:51 启动的下一轮试验完整运行 1800.31 秒，客户端按时关闭，启动器与测试助手均返回 0。原安装与 shadow 的 SDK 实际 SHA-256 均为 `9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723`。实际礼包购买序号 1706、TabId 10102033 返回 0，四件收藏变更通知成功；商城非零结果和预期漏回复均为 0。这些购买结果不证明礼包图片已经显示正常。

离线定位工具已保存基础 pak2 的 10782 条及 28 个热更新的 4880 条条目坐标，解开的三个推荐表相关包装均为 LOC 本地化数据。已知推荐内容前驱 entry 7141（头偏移 50501632）为加密包头；52 个大条目的首块检查没有取得可验证的纹理包归属。上述 LOC 名称和未命中结果均不能代替实际业务表或图片对象的来源。
