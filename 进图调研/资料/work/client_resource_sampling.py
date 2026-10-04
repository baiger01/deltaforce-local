"""Read-only discrete Windows resource snapshots for the bounded client test."""
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import psutil


class PerformanceInformation(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in (
            "CommitTotal", "CommitLimit", "CommitPeak", "PhysicalTotal", "PhysicalAvailable",
            "SystemCache", "KernelTotal", "KernelPaged", "KernelNonpaged", "PageSize")
    ] + [(name, wintypes.DWORD) for name in ("HandleCount", "ProcessCount", "ThreadCount")]


get_performance_info = ctypes.WinDLL("psapi", use_last_error=True).GetPerformanceInfo
get_performance_info.argtypes = [ctypes.POINTER(PerformanceInformation), wintypes.DWORD]
get_performance_info.restype = wintypes.BOOL


def capture_resources(elapsed_seconds, stage, owned):
    memory = psutil.virtual_memory()
    result = {
        "utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed_seconds, 2), "stage": stage,
        "physical_total_bytes": memory.total, "physical_available_bytes": memory.available,
        "cpu_percent_since_previous_sample": psutil.cpu_percent(interval=None),
        "owned_processes": [],
    }
    info = PerformanceInformation()
    info.cb = ctypes.sizeof(info)
    if get_performance_info(ctypes.byref(info), info.cb):
        result["system_commit_bytes"] = info.CommitTotal * info.PageSize
        result["system_commit_limit_bytes"] = info.CommitLimit * info.PageSize
        result["system_commit_peak_since_boot_bytes"] = info.CommitPeak * info.PageSize
    else:
        result["performance_info_windows_error"] = ctypes.get_last_error()
    for pid, created_at in list(owned.items()):
        try:
            process = psutil.Process(pid)
            if abs(process.create_time() - created_at) >= .01:
                continue
            result["owned_processes"].append({
                "pid": pid, "working_set_bytes": process.memory_info().rss,
                "cpu_seconds": round(sum(process.cpu_times()[:2]), 3),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
            result["owned_processes"].append({"pid": pid, "inspection_limit": type(error).__name__})
    return result


if __name__ == "__main__":
    import json
    print(json.dumps(capture_resources(0, "sampler_verification", {}), indent=2))
