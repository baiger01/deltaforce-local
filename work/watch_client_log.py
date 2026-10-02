"""Follow the local client's XOR-encoded log and keep relevant redacted alerts."""

import argparse
from pathlib import Path
import re
import sys
import time


ALERT = re.compile(
    r"拉取仓库数据失败|StartReconnectingNtf|OnReconnectLoginOperate|"
    r"InventoryServer.*(?:Error|Fail)|AuctionServer.*(?:Error|Fail)|"
    r"ShopServer.*(?:Error|Fail)|LuaMSafe.*(?:Error|Fail)|"
    r"ComparePriceLogic.*(?:Error|Fail)|登录组件异常|"
    r"QuickOperationLogic|WeaponBulletQuickOperationData|ProcessPbDataChange|"
    r"CSDeposit(?:OperateBullet|AssemblySyncBodyContainer|ChangeNtf)|"
    r"CSDeposit(?:Sort|SetCommonConfig|GetExtensionProps)|SafeBox|SafeAndCardPack|WarehouseArrange|"
    r"KeyBox|KeyCase|KeyCard|KeyChain|门卡|钥匙包|"
    r"CSWAssembly|AssemblyFail|AssembleFail|GunsmithServer|BattlePass|"
    r"InventoryServer:|QuickOperation.*(?:Error|Fail)|Weapon.*(?:Error|Fail|Invalid)|"
    r"GoodsItemStruct|SourcingAuctionProvider|ComparePriceLogic\.SimpleComparePrice|"
    r"_RefreshDurability|"
    r"MeleeWeapon|CSMelee|MeleeSkin|近战|DisplayCtrl_Knife|Displayctrl_Knife|"
    r"Mandel|Lottery|MysticalSkin|WeaponSkin|SkinInfo|ApplySkin|未知物品|曼德尔|"
    r"StoreServer|StoreMainUI|StoreMallGift|HeroServer|StaffLottery|商城|干员研究|"
    r"HeroLogic|HeroWatch|HeroAccessory|HeroBusinessCard|HeroVoice|HeroAction|"
    r"AccountServer.*(?:Error|Fail)|PlayerProfile|LoadImage.*(?:Error|Fail)|"
    r"RecommendBanner|RecommendHomepage|CheckPathValid|CDN.*(?:Error|Fail)|"
    r"UDFCDNImage:SetCDNImage|CDNDown DownFailed|ReqCdnDownload:|"
    r"FileExists.*(?:NotExist|HasExist)|PC CDNUrl IsEmpty|"
    r"Get CDNUrl =|Get New CDNUrl From Maple:|"
    r"OnMergeComplete|OnAllSkeletalMeshReady|AddWeaponDesc|OnAddWeapon|"
    r"Gunsmith.*(?:OperateBullet|InventoryError)|"
    r"LoadedClass is NULL|GuideHDWeakClickUI|IsForcedGuideActive_Special|"
    r"DoCommonPopTipShow Tips content|InputHelper: OnInputModeChanged|"
    r"InputModeCounter:.*Guide|AssemblyHDQuickOperationMainView|"
    r"请求超时|timed out|timeout|stack traceback|ScriptError|"
    r"Fatal error|Unhandled Exception",
    re.IGNORECASE,
)
SECRET = re.compile(r"(?i)(token|ticket|authorization)(\s*[:=]\s*)\S+")


def follow(source, target, duration_seconds, *, from_start=False, stop=None, ready=None, echo=False):
    target.parent.mkdir(parents=True, exist_ok=True)
    identity = None
    position = 0
    pending = b""
    alerts = 0
    deadline = time.monotonic() + duration_seconds
    with target.open("w", encoding="utf-8") as output:
        def emit(raw):
            nonlocal alerts
            line = raw.decode("utf-8", "replace").strip()
            if not ALERT.search(line):
                return
            line = SECRET.sub(r"\1\2[redacted]", line)[:700]
            output.write(line + "\n")
            output.flush()
            if echo:
                print(line, flush=True)
            alerts += 1

        while True:
            try:
                stat = source.stat()
            except FileNotFoundError:
                stat = None
            if stat is not None:
                current_identity = (stat.st_dev, stat.st_ino, stat.st_ctime_ns)
                if current_identity != identity or stat.st_size < position:
                    first = identity is None
                    identity = current_identity
                    position = 0 if from_start or not first or ready is not None and ready.is_set() else stat.st_size
                    pending = b""
                with source.open("rb") as stream:
                    stream.seek(position)
                    encoded = stream.read()
                    position = stream.tell()
                if position == len(encoded) and encoded.startswith(b"\xef\xbb\xbf"):
                    encoded = encoded[3:]
                pending += bytes(value ^ 0x5C for value in encoded)
                *complete, pending = pending.split(b"\n")
                for raw in complete:
                    emit(raw)
            if ready is not None:
                ready.set()
            if time.monotonic() >= deadline or stop is not None and stop.is_set():
                if pending:
                    emit(pending)
                break
            if stop is None:
                time.sleep(.5)
            else:
                stop.wait(.5)
    return alerts


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, default=780)
    parser.add_argument("--from-start", action="store_true")
    args = parser.parse_args()
    alerts = follow(args.source, args.output, args.duration_seconds,
                    from_start=args.from_start, echo=True)
    print(f"client_log_alerts={alerts}", flush=True)


if __name__ == "__main__":
    main()
