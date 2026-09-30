"""Follow the local client's XOR-encoded log and keep relevant redacted alerts."""

import argparse
from pathlib import Path
import re
import time


ALERT = re.compile(
    r"拉取仓库数据失败|StartReconnectingNtf|OnReconnectLoginOperate|"
    r"InventoryServer.*(?:Error|Fail)|AuctionServer.*(?:Error|Fail)|"
    r"ShopServer.*(?:Error|Fail)|LuaMSafe.*(?:Error|Fail)|"
    r"ComparePriceLogic.*(?:Error|Fail)|登录组件异常|"
    r"QuickOperationLogic|WeaponBulletQuickOperationData|ProcessPbDataChange|"
    r"CSDeposit(?:OperateBullet|AssemblySyncBodyContainer|ChangeNtf)|"
    r"InventoryServer:|QuickOperation.*(?:Error|Fail)|Weapon.*(?:Error|Fail|Invalid)|"
    r"GoodsItemStruct|SourcingAuctionProvider|ComparePriceLogic\.SimpleComparePrice|"
    r"_RefreshDurability|"
    r"MeleeWeapon|CSMelee|MeleeSkin|近战|DisplayCtrl_Knife|Displayctrl_Knife|"
    r"Mandel|Lottery|MysticalSkin|WeaponSkin|SkinInfo|ApplySkin|未知物品|曼德尔|"
    r"OnMergeComplete|OnAllSkeletalMeshReady|AddWeaponDesc|OnAddWeapon|"
    r"Gunsmith.*(?:OperateBullet|InventoryError)|"
    r"LoadedClass is NULL|GuideHDWeakClickUI|IsForcedGuideActive_Special|"
    r"DoCommonPopTipShow Tips content|InputHelper: OnInputModeChanged|"
    r"InputModeCounter:.*Guide|AssemblyHDQuickOperationMainView|"
    r"Fatal error|Unhandled Exception",
    re.IGNORECASE,
)
SECRET = re.compile(r"(?i)(token|ticket|authorization)(\s*[:=]\s*)\S+")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, default=390)
    parser.add_argument("--from-start", action="store_true")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    identity = None
    position = 0
    pending = b""
    alerts = 0
    deadline = time.monotonic() + args.duration_seconds
    with args.output.open("w", encoding="utf-8") as output:
        while time.monotonic() < deadline:
            try:
                stat = args.source.stat()
            except FileNotFoundError:
                time.sleep(0.5)
                continue
            current_identity = (stat.st_dev, stat.st_ino, stat.st_ctime_ns)
            if current_identity != identity or stat.st_size < position:
                first = identity is None
                identity = current_identity
                position = 0 if args.from_start or not first else stat.st_size
                pending = b""
            with args.source.open("rb") as source:
                source.seek(position)
                encoded = source.read()
                position = source.tell()
            if position == len(encoded) and encoded.startswith(b"\xef\xbb\xbf"):
                encoded = encoded[3:]
            pending += bytes(value ^ 0x5C for value in encoded)
            *complete, pending = pending.split(b"\n")
            for raw in complete:
                line = raw.decode("utf-8", "replace").strip()
                if not ALERT.search(line):
                    continue
                line = SECRET.sub(r"\1\2[redacted]", line)[:700]
                output.write(line + "\n")
                output.flush()
                print(line, flush=True)
                alerts += 1
            time.sleep(0.5)
    print(f"client_log_alerts={alerts}", flush=True)


if __name__ == "__main__":
    main()
