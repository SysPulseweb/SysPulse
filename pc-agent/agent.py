import os
import sys
import time
import json
import uuid
import socket
import getpass
import platform
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

import requests
import psutil


# ============================================================
# VERSION
# ============================================================
AGENT_VERSION = "2.0.0"


# ============================================================
# PATHS (works for .py and .exe)
# ============================================================
def get_base_dir() -> str:
    """
    If running as a PyInstaller EXE, sys.executable points to the exe path.
    If running as a script, __file__ points to the .py path.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = get_base_dir()
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
DEVICE_ID_PATH = os.path.join(BASE_DIR, "device_id.txt")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_PATH = os.path.join(LOG_DIR, "agent.log")


# ============================================================
# LOGGING (simple rotation)
# ============================================================
LOG_MAX_BYTES = 2_000_000  # 2MB
LOG_BACKUPS = 3


def _rotate_logs() -> None:
    try:
        if not os.path.exists(LOG_PATH):
            return
        if os.path.getsize(LOG_PATH) < LOG_MAX_BYTES:
            return

        # Rotate: agent.log -> agent.log.1 -> agent.log.2 ...
        for i in range(LOG_BACKUPS, 0, -1):
            src = f"{LOG_PATH}.{i}"
            dst = f"{LOG_PATH}.{i+1}"
            if os.path.exists(src):
                if i == LOG_BACKUPS:
                    try:
                        os.remove(src)
                    except Exception:
                        pass
                else:
                    try:
                        os.replace(src, dst)
                    except Exception:
                        pass

        try:
            os.replace(LOG_PATH, f"{LOG_PATH}.1")
        except Exception:
            pass
    except Exception:
        pass


def log(msg: str) -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    _rotate_logs()
    line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ============================================================
# CONFIG
# ============================================================
DEFAULT_CONFIG: Dict[str, Any] = {
    "server": "http://PC-DATECSA-USC:8000",
    "token": "changeme",         # agent token (X-Agent-Token)
    "interval": 10,              # seconds between reports
    "top_n": 5,                  # top processes
    "timeout": 5,                # request timeout seconds
    "verify_tls": True,          # https cert verification
    "disk_path": "",             # optional override (e.g. "D:\\" or "/")
    "regen_device_id": False,    # if true, generates a new device_id and resets to false
}


def load_config() -> Dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)

    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            if isinstance(user_cfg, dict):
                cfg.update(user_cfg)
        except Exception as e:
            log(f"CONFIG ERROR: {e} (file: {CONFIG_PATH})")
    else:
        log(f"CONFIG not found at: {CONFIG_PATH} (using defaults)")

    # Env override (priority over file)
    env_token = os.getenv("AGENT_TOKEN", "").strip()
    if env_token:
        cfg["token"] = env_token

    return cfg


def save_config(cfg: Dict[str, Any]) -> None:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        log(f"CONFIG SAVE ERROR: {e}")


# ============================================================
# DEVICE ID (stable per PC)
# ============================================================
def get_device_id(regen: bool = False) -> str:
    if regen:
        new_id = str(uuid.uuid4())
        try:
            with open(DEVICE_ID_PATH, "w", encoding="utf-8") as f:
                f.write(new_id)
        except Exception as e:
            log(f"WARNING: could not write device_id.txt: {e}")
        return new_id

    if os.path.exists(DEVICE_ID_PATH):
        try:
            with open(DEVICE_ID_PATH, "r", encoding="utf-8") as f:
                v = f.read().strip()
                if v:
                    return v
        except Exception:
            pass

    new_id = str(uuid.uuid4())
    try:
        with open(DEVICE_ID_PATH, "w", encoding="utf-8") as f:
            f.write(new_id)
    except Exception as e:
        log(f"WARNING: could not write device_id.txt: {e}")
    return new_id


# ============================================================
# SYSTEM HELPERS
# ============================================================
def get_os_name() -> str:
    s = platform.system().lower()
    if "windows" in s:
        return "Windows"
    if "linux" in s:
        return "Linux"
    if "darwin" in s or "mac" in s:
        return "macOS"
    return platform.system()


def get_disk_path(cfg: Dict[str, Any]) -> str:
    # explicit override
    dp = str(cfg.get("disk_path", "")).strip()
    if dp:
        return dp

    # default by OS
    if get_os_name().lower() == "windows":
        return "C:\\"
    return "/"


def get_local_ip() -> str:
    # best-effort: route to a public IP to get selected interface
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def safe_proc_name(p: psutil.Process) -> str:
    try:
        n = p.name()
        return n if n else "?"
    except Exception:
        return "?"


def get_disk_usage(path: str) -> Tuple[float, float]:
    try:
        d = psutil.disk_usage(path)
        return float(d.used), float(d.total)
    except Exception:
        return 0.0, 0.0


def collect_top_processes(top_n: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Returns:
      top_cpu: [{pid,name,cpu,rss}, ...]
      top_ram: [{pid,name,cpu,rss}, ...]
    Notes:
      - cpu_percent needs warmup
      - some processes will throw AccessDenied
    """
    items: List[Dict[str, Any]] = []
    procs: List[psutil.Process] = []

    # collect processes
    for p in psutil.process_iter(["pid"]):
        procs.append(p)

    # warm-up
    for p in procs:
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass

    time.sleep(0.08)

    for p in procs:
        try:
            cpu = float(p.cpu_percent(interval=None))
            rss = float(p.memory_info().rss)
            items.append(
                {
                    "pid": int(p.pid),
                    "name": safe_proc_name(p),
                    "cpu": cpu,
                    "rss": rss,
                }
            )
        except Exception:
            continue

    top_cpu = sorted(items, key=lambda x: x["cpu"], reverse=True)[: max(1, top_n)]
    top_ram = sorted(items, key=lambda x: x["rss"], reverse=True)[: max(1, top_n)]
    return top_cpu, top_ram


# ============================================================
# MAIN LOOP
# ============================================================
def main() -> None:
    cfg = load_config()

    # regen device id if requested in config
    regen = bool(cfg.get("regen_device_id", False))
    device_id = get_device_id(regen=regen)
    if regen:
        cfg["regen_device_id"] = False
        save_config(cfg)

    server = str(cfg.get("server", "")).strip().rstrip("/")
    token = str(cfg.get("token", "")).strip()
    interval = int(cfg.get("interval", 10))
    top_n = int(cfg.get("top_n", 5))
    timeout = int(cfg.get("timeout", 5))
    verify_tls = bool(cfg.get("verify_tls", True))
    disk_path = get_disk_path(cfg)

    if not server:
        log("ERROR: 'server' vacío en config.json")
        time.sleep(10)
        return

    if not token or token.lower() == "changeme":
        log("ERROR: token inválido. Edita config.json (campo 'token') o define AGENT_TOKEN en env.")
        time.sleep(10)
        return

    hostname = socket.gethostname()
    os_name = get_os_name()
    username = ""
    try:
        username = getpass.getuser()
    except Exception:
        username = ""

    local_ip = get_local_ip()
    boot_time = float(psutil.boot_time())

    log("--------------------------------------------------")
    log("SysPulse Agent starting")
    log(f"AGENT_VERSION: {AGENT_VERSION}")
    log(f"BASE_DIR: {BASE_DIR}")
    log(f"CONFIG_PATH: {CONFIG_PATH}")
    log(f"DEVICE_ID: {device_id}")
    log(f"HOSTNAME: {hostname} | OS: {os_name} | USER: {username} | IP: {local_ip}")
    log(f"SERVER: {server}")
    log(f"INTERVAL: {interval}s, TOP_N: {top_n}, TIMEOUT: {timeout}s, VERIFY_TLS: {verify_tls}")
    log(f"DISK_PATH: {disk_path}")
    log("--------------------------------------------------")

    url = f"{server}/api/report"
    headers = {"X-Agent-Token": token}

    # Backoff for network errors
    backoff = 1
    backoff_max = 60

    while True:
        try:
            # CPU (blocking 1s for a stable reading)
            cpu = float(psutil.cpu_percent(interval=1))

            # RAM
            vm = psutil.virtual_memory()
            ram_used = float(vm.used)
            ram_total = float(vm.total)

            # Disk
            disk_used, disk_total = get_disk_usage(disk_path)

            # Uptime
            uptime_sec = float(time.time() - psutil.boot_time())

            # Processes
            top_cpu, top_ram = collect_top_processes(top_n)

            payload: Dict[str, Any] = {
                "device_id": device_id,
                "hostname": hostname,
                "os": os_name,

                "cpu": cpu,
                "ram_used": ram_used,
                "ram_total": ram_total,
                "disk_used": disk_used,
                "disk_total": disk_total,
                "uptime_sec": uptime_sec,

                "processes_top_cpu": top_cpu,
                "processes_top_ram": top_ram,

                # extra metadata (server puede ignorar si no lo usa)
                "agent_version": AGENT_VERSION,
                "local_ip": local_ip,
                "username": username,
                "boot_time": boot_time,
            }

            r = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=timeout,
                verify=verify_tls,
            )

            if r.status_code == 200:
                log("Sent report: 200")
                backoff = 1
                time.sleep(max(1, interval))
            else:
                # Non-200 from server (e.g., 401/403/500)
                txt = ""
                try:
                    txt = r.text[:220]
                except Exception:
                    txt = ""
                log(f"Server responded {r.status_code}: {txt}")
                time.sleep(max(2, interval))

        except requests.exceptions.RequestException as e:
            log(f"NET ERROR: {e} (retry in {backoff}s)")
            time.sleep(backoff)
            backoff = min(backoff * 2, backoff_max)

        except Exception as e:
            log(f"ERROR: {e}")
            time.sleep(max(2, interval))


if __name__ == "__main__":
    main()