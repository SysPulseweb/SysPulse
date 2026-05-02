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
AGENT_VERSION = "2.2.0-pro-discovery"


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
DEVICE_META_PATH = os.path.join(BASE_DIR, "device_meta.json")
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

    # Ubicación del PC
    # Exacta: manual_location=true y llena latitude/longitude/location.
    # Automática: auto_location=true. Usa geolocalización por IP pública, no GPS.
    "manual_location": False,
    "location": "",
    "latitude": None,
    "longitude": None,

    "auto_location": True,
    "location_refresh_minutes": 60,
    "location_timeout": 5,
    "location_provider": "https://ipapi.co/json/",
    "location_provider_fallback": "http://ip-api.com/json/",

    # Evita que varios PCs se mezclen si copiaste la carpeta con device_id.txt.
    "auto_regen_id_on_hostname_change": True,

    # Descubrimiento automático del servidor SysPulse en red local.
    # Útil cuando no hay IP fija y el nombre del servidor no resuelve.
    "auto_discover_server": True,
    "discovery_port": 8000,
    "discovery_timeout": 0.35,
    "discovery_max_workers": 80,
    "server_candidates": [
        "http://PC-DATECSA-USC:8000",
        "http://PC-DATECSA-USC.local:8000"
    ],
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
        log(f"CONFIG not found at: {CONFIG_PATH} (creating default config)")
        save_config(cfg)

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
def _read_json_file(path: str) -> Dict[str, Any]:
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _write_json_file(path: str, data: Dict[str, Any]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        log(f"WARNING: could not write {os.path.basename(path)}: {e}")


def _new_device_id() -> str:
    new_id = str(uuid.uuid4())
    try:
        with open(DEVICE_ID_PATH, "w", encoding="utf-8") as f:
            f.write(new_id)
    except Exception as e:
        log(f"WARNING: could not write device_id.txt: {e}")
    return new_id


def get_device_id(regen: bool = False, cfg: Optional[Dict[str, Any]] = None) -> str:
    """
    ID estable por PC.

    PRO:
    - Si regen_device_id=true, genera uno nuevo.
    - Si detecta carpeta copiada a otro PC con el mismo device_id.txt,
      genera un ID nuevo automáticamente para evitar que se mezclen.
    """
    hostname = socket.gethostname()
    local_ip = get_local_ip()
    cfg = cfg or {}

    if regen:
        new_id = _new_device_id()
        _write_json_file(DEVICE_META_PATH, {
            "device_id": new_id,
            "hostname": hostname,
            "local_ip": local_ip,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "reason": "regen_device_id",
        })
        return new_id

    existing_id = ""
    if os.path.exists(DEVICE_ID_PATH):
        try:
            with open(DEVICE_ID_PATH, "r", encoding="utf-8") as f:
                existing_id = f.read().strip()
        except Exception:
            existing_id = ""

    meta = _read_json_file(DEVICE_META_PATH)
    meta_hostname = str(meta.get("hostname", "")).strip().lower()
    current_hostname = hostname.strip().lower()

    if existing_id:
        if bool(cfg.get("auto_regen_id_on_hostname_change", True)) and meta_hostname and meta_hostname != current_hostname:
            log(
                "DEVICE_ID WARNING: device_id.txt parece copiado desde otro PC. "
                f"Meta hostname='{meta.get('hostname')}', hostname actual='{hostname}'. Generando ID nuevo."
            )
            existing_id = _new_device_id()
            _write_json_file(DEVICE_META_PATH, {
                "device_id": existing_id,
                "hostname": hostname,
                "local_ip": local_ip,
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "reason": "hostname_changed_auto_regen",
            })
            return existing_id

        if not meta:
            _write_json_file(DEVICE_META_PATH, {
                "device_id": existing_id,
                "hostname": hostname,
                "local_ip": local_ip,
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "reason": "metadata_created_for_existing_id",
            })
        return existing_id

    new_id = _new_device_id()
    _write_json_file(DEVICE_META_PATH, {
        "device_id": new_id,
        "hostname": hostname,
        "local_ip": local_ip,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "reason": "new_install",
    })
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
# SERVER DISCOVERY HELPERS
# ============================================================
def _normalize_server_url(url: str) -> str:
    url = str(url or "").strip().rstrip("/")
    if not url:
        return ""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url


def _server_health_ok(server_url: str, timeout: float = 1.5) -> bool:
    server_url = _normalize_server_url(server_url)
    if not server_url:
        return False

    for path in ["/api/health", "/"]:
        try:
            r = requests.get(server_url + path, timeout=timeout)
            if r.status_code in (200, 401, 403):
                return True
        except Exception:
            pass
    return False


def _get_local_ipv4_candidates() -> List[str]:
    ips: List[str] = []

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            ips.append(ip)
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass

    return ips


def _scan_host_for_server(ip: str, port: int, timeout: float) -> Optional[str]:
    url = f"http://{ip}:{port}"
    try:
        r = requests.get(url + "/api/health", timeout=timeout)
        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict) and (data.get("status") == "ok" or "retention_days" in data):
                    return url
            except Exception:
                return url
    except Exception:
        return None
    return None


def discover_server_on_lan(cfg: Dict[str, Any]) -> str:
    """
    Descubre el servidor SysPulse sin IP fija.

    Orden:
    1. server configurado.
    2. server_candidates.
    3. Escaneo de la subred local /24 por el puerto 8000.
    """
    current_server = _normalize_server_url(cfg.get("server", ""))
    timeout = float(cfg.get("discovery_timeout", 0.35))
    port = int(cfg.get("discovery_port", 8000))

    placeholders = ["IP_O_NOMBRE_DEL_SERVIDOR", "ip_o_nombre_del_servidor"]
    if current_server and not any(p.lower() in current_server.lower() for p in placeholders):
        if _server_health_ok(current_server, timeout=1.2):
            return current_server

    candidates = cfg.get("server_candidates", []) or []
    for candidate in candidates:
        candidate = _normalize_server_url(candidate)
        if candidate and _server_health_ok(candidate, timeout=1.2):
            log(f"DISCOVERY OK: servidor encontrado por candidato: {candidate}")
            return candidate

    if not bool(cfg.get("auto_discover_server", True)):
        return current_server

    local_ips = _get_local_ipv4_candidates()
    if not local_ips:
        log("DISCOVERY WARNING: no se pudo determinar IP local para escanear red.")
        return current_server

    max_workers = int(cfg.get("discovery_max_workers", 80))
    checked_networks = set()

    for local_ip in local_ips:
        try:
            network = ipaddress.ip_network(local_ip + "/24", strict=False)
        except Exception:
            continue

        if str(network) in checked_networks:
            continue
        checked_networks.add(str(network))

        log(f"DISCOVERY: buscando servidor SysPulse en red {network} puerto {port}...")

        hosts = [str(ip) for ip in network.hosts()]
        try:
            local_last = int(local_ip.split(".")[-1])
            hosts.sort(key=lambda x: abs(int(x.split(".")[-1]) - local_last))
        except Exception:
            pass

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_scan_host_for_server, ip, port, timeout): ip
                for ip in hosts
            }
            for fut in as_completed(futures):
                found = fut.result()
                if found:
                    log(f"DISCOVERY OK: servidor encontrado automáticamente: {found}")
                    cfg["server"] = found
                    try:
                        save_config(cfg)
                        log("DISCOVERY: config.json actualizado con el servidor encontrado.")
                    except Exception:
                        pass
                    return found

    log("DISCOVERY WARNING: no se encontró servidor SysPulse en la red local.")
    return current_server



# ============================================================
# LOCATION HELPERS
# ============================================================
def _parse_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        if isinstance(value, str) and not value.strip():
            return None
        return float(value)
    except Exception:
        return None


def get_manual_location(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ubicación manual exacta desde config.json.
    Úsala si quieres que cada PC aparezca exactamente en su oficina/sala.
    """
    if not bool(cfg.get("manual_location", False)):
        return {}

    lat = _parse_float(cfg.get("latitude"))
    lng = _parse_float(cfg.get("longitude"))

    if lat is None or lng is None:
        log("LOCATION WARNING: manual_location=true pero latitude/longitude están vacíos o inválidos.")
        return {}

    return {
        "latitude": lat,
        "longitude": lng,
        "location": str(cfg.get("location", "") or "Ubicación manual").strip() or "Ubicación manual",
        "public_ip": "",
        "location_source": "manual",
        "location_provider": "config.json",
    }


def _location_from_provider(provider: str, timeout: int) -> Dict[str, Any]:
    r = requests.get(provider, timeout=timeout)
    if r.status_code != 200:
        log(f"LOCATION WARNING: provider {provider} returned {r.status_code}")
        return {}

    data = r.json() if r.content else {}
    if not isinstance(data, dict):
        return {}

    lat = data.get("latitude")
    lng = data.get("longitude")
    city = data.get("city") or ""
    region = data.get("region") or data.get("region_name") or ""
    country = data.get("country_name") or data.get("country") or ""
    ip = data.get("ip") or data.get("query") or ""

    if lat is None:
        lat = data.get("lat")
    if lng is None:
        lng = data.get("lon")
    if not region:
        region = data.get("regionName") or ""

    lat = _parse_float(lat)
    lng = _parse_float(lng)

    if lat is None or lng is None:
        return {}

    location_parts = [str(x).strip() for x in [city, region, country] if str(x or "").strip()]
    location_name = ", ".join(location_parts) if location_parts else "Ubicación automática por IP"

    return {
        "latitude": lat,
        "longitude": lng,
        "location": location_name,
        "public_ip": ip,
        "location_source": "ip",
        "location_provider": provider,
    }


def get_public_location(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ubicación automática por IP pública.

    IMPORTANTE:
    - No es GPS.
    - Depende del proveedor de internet.
    - Si varios PCs salen por la misma red, pueden compartir ubicación similar.
    - Para ubicación exacta, usa manual_location=true en config.json.
    """
    manual = get_manual_location(cfg)
    if manual:
        return manual

    if not bool(cfg.get("auto_location", True)):
        return {}

    timeout = int(cfg.get("location_timeout", 5))
    providers = [
        str(cfg.get("location_provider", "https://ipapi.co/json/")).strip(),
        str(cfg.get("location_provider_fallback", "http://ip-api.com/json/")).strip(),
    ]

    for provider in [p for p in providers if p]:
        try:
            loc = _location_from_provider(provider, timeout)
            if loc:
                return loc
        except Exception as e:
            log(f"LOCATION ERROR with {provider}: {e}")

    return {}


# ============================================================
# MAIN LOOP
# ============================================================
def main() -> None:
    cfg = load_config()

    # regen device id if requested in config
    regen = bool(cfg.get("regen_device_id", False))
    device_id = get_device_id(regen=regen, cfg=cfg)
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

    if "127.0.0.1" in server or "localhost" in server.lower():
        log("WARNING: el server apunta a localhost/127.0.0.1. En otros PCs debe ser la IP o nombre del servidor real.")

    # Plug & Play: si el nombre/IP configurado no funciona, busca el servidor en la red local.
    discovered_server = discover_server_on_lan(cfg)
    if discovered_server:
        server = discovered_server.rstrip("/")
    else:
        log("ERROR: no se pudo resolver ni descubrir el servidor SysPulse. Revisa red/firewall/puerto 8000.")

    hostname = socket.gethostname()
    os_name = get_os_name()
    username = ""
    try:
        username = getpass.getuser()
    except Exception:
        username = ""

    local_ip = get_local_ip()
    boot_time = float(psutil.boot_time())

    # Ubicación cacheada para no consultar el proveedor en cada reporte
    location_cache: Dict[str, Any] = {}
    location_next_refresh = 0.0
    location_refresh_seconds = max(60, int(cfg.get("location_refresh_minutes", 60)) * 60)

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
    log(f"MANUAL_LOCATION: {bool(cfg.get('manual_location', False))} | AUTO_LOCATION: {bool(cfg.get('auto_location', True))} | REFRESH: {cfg.get('location_refresh_minutes', 60)} min")
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

            # Ubicación automática por IP pública
            if bool(cfg.get("auto_location", True)) and time.time() >= location_next_refresh:
                new_location = get_public_location(cfg)
                if new_location:
                    location_cache = new_location
                    log(
                        "LOCATION OK: "
                        f"{location_cache.get('latitude')}, {location_cache.get('longitude')} "
                        f"{location_cache.get('location', '')}"
                    )
                location_next_refresh = time.time() + location_refresh_seconds

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
                "base_dir": BASE_DIR,

                # ubicación automática del PC agente
                "location": location_cache.get("location", ""),
                "latitude": location_cache.get("latitude"),
                "longitude": location_cache.get("longitude"),
                "public_ip": location_cache.get("public_ip", ""),
                "location_source": location_cache.get("location_source", ""),
                "location_provider": location_cache.get("location_provider", ""),
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