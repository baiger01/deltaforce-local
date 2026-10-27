# 换电脑继续开发

本仓库的 `main` 是唯一版本。直接克隆仓库即可取得服务端、协议目录、工具、历史与当前版本的必要来源证据。所有下列命令均在仓库根目录执行，不依赖旧电脑的盘符或另一个工作区。

Windows 建议选择层级较短的检出目录。Git 已通过下列克隆参数启用长路径；若系统和 Python 仍受长路径限制，使用较短目录或先启用系统长路径支持，再校验完整证据树。

## 拉取和校验

```powershell
git clone -c core.longpaths=true https://github.com/baiger01/deltaforce-local.git
cd deltaforce-local
git switch main
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r outputs/df-local-server/requirements-optional.txt
.\.venv\Scripts\python.exe -B work/git_runtime_manifest.py --verify
```

依赖清单逐文件校验 SHA-256 和大小，包含运行使用的封存证据与资源。封存文件必须保留原始字节，不能格式化 JSON、自动换行或修改客户端哈希来绕过校验。历史采样中的位置字段是来源记录，不能作为新电脑的安装路径使用。

## 服务端测试

```powershell
Push-Location outputs/df-local-server
try {
    & ..\..\.venv\Scripts\python.exe -B -m unittest discover -s tests -q
} finally {
    Pop-Location
}
```

服务端领域职责见 [源码入口](outputs/df-local-server/dfserver/README.md)。网页入口执行 `outputs/df-local-server/open-local-entrance.cmd`；账号数据库在首次使用时创建，不随公开 Git 仓库分发。

## 原客户端环境

自行准备匹配版本的游戏安装、Python 3.12 及可从命令行调用的 Zig 编译器。游戏完整安装、账号数据库、密码、登录票据和编译产物不属于 Git 开发依赖。

默认布局为同一父目录下的 `deltaforce-local/`、`game/` 和 `shadow/`。游戏在其它位置时，由新电脑设置两个环境变量；相对值均以仓库根目录解析。安装目录与影子目录必须独立，硬链接模式要求同一磁盘卷。

```powershell
$env:DF_LOCAL_SOURCE_GAME = "../game"
$env:DF_LOCAL_SHADOW_GAME = "../shadow"
$zigCompiler = (Get-Command zig -ErrorAction Stop).Source
.\.venv\Scripts\python.exe -B work/create_local_client_shadow.py
.\.venv\Scripts\python.exe -B outputs/native-account-provider/build_provider.py --sdk "$env:DF_LOCAL_SOURCE_GAME/DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll" --compiler "$zigCompiler" --stage work/sdk-local-provider-stage
.\.venv\Scripts\python.exe -B outputs/native-account-provider/verify_provider.py --sdk "$env:DF_LOCAL_SOURCE_GAME/DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll" --stage work/sdk-local-provider-stage
```

当前 Shipping SHA-256 为 `79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203`。SDK SHA-256 为 `9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723`。版本不同时应重新研究并生成独立配置，不能替换旧 SHA 继续使用。

按[运行说明](docs/RUNNING.md)建立自己的测试账号后，用统一入口启动 1800 秒验证：

```powershell
.\.venv\Scripts\python.exe -B work/run_local_game.py --observation-seconds 1800 --native-username YOUR_LOCAL_USERNAME
```

当前新版只接入诊断入场方案，用户最近一次仍无法进入地图。第五个移动复制对象和外观字段已通过离线测试，尚未进行新一轮实机验证。随机出生、物资、曼德尔砖、HUD 和玩法初始化还没有完成新版迁移。后续从[当前入场交接](docs/HANDOFF_CURRENT_ENTRY_20261027.md)继续，不能按完整玩法验收。

每轮测试结束检查 `original_sdk_restored`、配置恢复记录及剩余测试进程；源码在实机测试期间保持冻结。不要在原安装目录替换 SDK。
