import base64
import binascii
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from . import log
from .config import settings
from .model import DOWN, Point

XRAY_ERROR = re.compile(r"failed|rejected|refused|timeout|bad status code|unauthenticated", re.I)
GEO_ERROR = re.compile(r"geosite|geoip|code not found", re.I)


class TunnelError(Exception):
    pass


def check_all(probe):
    try:
        entries = fetch_subscription()
    except (OSError, RuntimeError) as e:
        log(f"подписка недоступна: {e}")
        return [Point("node", "подписка", note=f"не удалось получить узлы: {e}")]
    with ThreadPoolExecutor(settings.workers) as pool:
        return list(pool.map(lambda entry: check_node(entry, probe), entries))


def fetch_subscription():
    # без этих заголовков remnawave отдаёт заглушку "Приложение не поддерживается"
    req = urllib.request.Request(settings.sub_url, headers={
        "User-Agent": "Happ/1.0",
        "X-HWID": settings.sub_hwid,
        "X-Device-OS": "Linux",
        "X-Ver-OS": "1",
        "X-Device-Model": "gemini-check",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode()
        routing = resp.headers.get("routing", "")
    try:
        entries = json.loads(body)
    except ValueError:
        raise RuntimeError("панель отдала заглушку вместо конфигов") from None
    if not isinstance(entries, list):
        raise RuntimeError("подписка вернула не список конфигов")
    update_geo_files(routing)
    return entries


def check_node(entry, probe):
    point = Point("node", entry.get("remarks") or "без имени")
    try:
        probe_through(entry, point, probe)
        return point
    except TunnelError as e:
        if not GEO_ERROR.search(str(e)):
            point.status, point.note = DOWN, f"xray не запустился: {e}"
            return point

    # в geo файлах нет категорий из правил подписки, пробуем без правил
    bare = {k: v for k, v in entry.items() if k not in ("dns", "routing")}
    try:
        probe_through(bare, point, probe)
    except TunnelError as e:
        point.status, point.note = DOWN, f"xray не запустился: {e}"
        return point
    point.note = ", ".join(filter(None, [point.note, "без правил подписки"]))
    return point


def probe_through(entry, point, probe):
    with tunnel(entry) as (proxy, xray_log):
        probe(point, proxy)
        if point.status == DOWN and not point.exit_ip:
            point.note = why_down(entry, last_error(xray_log))


@contextmanager
def tunnel(entry):
    port = free_port()
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp, "config.json")
        xray_log = Path(tmp, "xray.log")
        config.write_text(json.dumps(xray_config(entry, port)), encoding="utf-8")
        with open(xray_log, "w") as out:
            proc = subprocess.Popen([str(settings.xray_bin), "run", "-c", str(config)],
                                    stdout=out, stderr=subprocess.STDOUT,
                                    start_new_session=True)
        try:
            if not wait_port(port):
                raise TunnelError(last_error(xray_log) or "локальный порт не открылся")
            yield f"socks5h://127.0.0.1:{port}", xray_log
        finally:
            kill(proc)


def xray_config(entry, port):
    config = {
        "log": {"loglevel": "info"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"udp": True, "auth": "noauth"}}],
        "outbounds": entry.get("outbounds", []),
    }
    for key in ("dns", "routing", "observatory", "burstObservatory"):
        if entry.get(key):
            config[key] = entry[key]

    # leastPing балансер без observatory не запускается
    # ("not all dependencies are resolved"), happ его добавляет сам
    selector = []
    for b in entry.get("routing", {}).get("balancers", []):
        selector += b.get("selector", [])
    if selector and "observatory" not in config and "burstObservatory" not in config:
        config["observatory"] = {"subjectSelector": selector,
                                 "probeUrl": "https://www.gstatic.com/generate_204",
                                 "probeInterval": "10m", "enableConcurrency": True}
    return config


def why_down(entry, xray_error):
    server = server_address(entry)
    if server and not reachable(*server):
        return f"хост {server[0]}:{server[1]} не отвечает"
    if xray_error:
        return f"туннель не поднялся: {xray_error}"
    return "хост отвечает, но через туннель трафик не идёт"


def server_address(entry):
    for ob in entry.get("outbounds", []):
        if ob.get("protocol") in ("vless", "vmess", "trojan", "shadowsocks"):
            s = ob.get("settings", {})
            servers = s.get("vnext") or s.get("servers") or []
            if servers:
                return servers[0].get("address"), int(servers[0].get("port"))
    return None


def reachable(host, port):
    try:
        with socket.create_connection((host, port), timeout=6):
            return True
    except OSError:
        return False


def last_error(xray_log):
    try:
        lines = xray_log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for line in reversed(lines[-200:]):
        if XRAY_ERROR.search(line):
            msg = re.sub(r"^\S+ \S+ ", "", line)  # время
            msg = re.sub(r"\[\w+\] ", "", msg)
            msg = msg.split(" > ")[-1]  # у xray сама причина в конце
            return re.sub(r"^[\w/]+: ", "", msg).strip()[:110]
    return ""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def kill(proc):
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
    proc.wait(timeout=5)


geo_lock = threading.Lock()
geo_done = set()


def update_geo_files(routing):
    # в правилах подписки свои категории (geosite:category-ru-whitelist и т.д.),
    # в стандартных geo файлах xray их нет. ссылки на нужные файлы панель
    # присылает в заголовке routing: happ://routing/onadd/<base64 json>
    m = re.search(r"/onadd/([\w=-]+)", routing)
    if not m:
        return
    raw = m.group(1)
    try:
        info = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, binascii.Error):
        log("не разобрал заголовок routing")
        return

    with geo_lock:
        for key, name in (("Geoipurl", "geoip.dat"), ("Geositeurl", "geosite.dat")):
            url = info.get(key)
            if not url or url in geo_done:
                continue
            path = settings.xray_bin.parent / name
            tmp = path.with_suffix(".part")
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Happ/1.0"})
                with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as f:
                    shutil.copyfileobj(resp, f)
            except OSError as e:
                log(f"{name} не скачался, остаётся стандартный: {e}")
                continue
            tmp.replace(path)
            geo_done.add(url)
            log(f"{name} скачан из панели")
