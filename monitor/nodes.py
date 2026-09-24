"""Узлы подписки. Для каждого поднимается временный Xray с конфигом из
подписки — вместе с её routing и dns, то есть ровно с тем, что получает клиент."""

from __future__ import annotations

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
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from . import log
from .config import settings
from .model import DOWN, Point
from .probes import Probe

XRAY_FAILURE = re.compile(r"failed|rejected|refused|timeout|bad status code|unauthenticated", re.I)
GEO_FAILURE = re.compile(r"geosite|geoip|code not found", re.I)


class TunnelError(Exception):
    pass


def check_all(probe: Probe) -> list[Point]:
    try:
        entries = fetch_subscription()
    except (OSError, RuntimeError) as exc:
        log(f"подписка недоступна: {exc}")
        return [Point("node", "подписка", note=f"список узлов не получен: {exc}")]
    with ThreadPoolExecutor(settings.workers) as pool:
        return list(pool.map(lambda entry: check_node(entry, probe), entries))


def fetch_subscription() -> list[dict]:
    # Без заголовков устройства Remnawave вместо конфигов отдаёт заглушку
    # «Приложение не поддерживается».
    request = urllib.request.Request(settings.sub_url, headers={
        "User-Agent": "Happ/1.0",
        "X-HWID": settings.sub_hwid,
        "X-Device-OS": "Linux",
        "X-Ver-OS": "1",
        "X-Device-Model": "gemini-check",
    })
    with urllib.request.urlopen(request, timeout=30) as resp:
        body = resp.read().decode()
        routing = resp.headers.get("routing", "")
    try:
        entries = json.loads(body)
    except ValueError:
        raise RuntimeError("панель не признала клиента и отдала заглушку") from None
    if not isinstance(entries, list):
        raise RuntimeError("подписка отдала не список конфигов")
    _sync_geo_files(routing)
    return entries


def check_node(entry: dict, probe: Probe) -> Point:
    point = Point("node", entry.get("remarks") or "без имени")
    try:
        _probe_through(entry, point, probe)
        return point
    except TunnelError as exc:
        if not GEO_FAILURE.search(str(exc)):
            point.status, point.note = DOWN, f"Xray не запустился: {exc}"
            return point

    # В geo-файлах не нашлось категорий из правил подписки — проверяем без правил.
    bare = {key: value for key, value in entry.items() if key not in ("dns", "routing")}
    try:
        _probe_through(bare, point, probe)
    except TunnelError as exc:
        point.status, point.note = DOWN, f"Xray не запустился: {exc}"
        return point
    point.note = " · ".join(filter(None, (point.note, "без правил подписки")))
    return point


def _probe_through(entry: dict, point: Point, probe: Probe) -> None:
    with tunnel(entry) as (proxy, xray_log):
        probe(point, proxy)
        if point.status == DOWN and not point.exit_ip:
            point.note = _why_down(entry, _last_error(xray_log))


@contextmanager
def tunnel(entry: dict) -> Iterator[tuple[str, Path]]:
    """Xray с конфигом узла; отдаёт адрес локального SOCKS и путь к логу."""
    port = _free_port()
    with tempfile.TemporaryDirectory() as tmp:
        config, xray_log = Path(tmp, "config.json"), Path(tmp, "xray.log")
        config.write_text(json.dumps(_xray_config(entry, port)), encoding="utf-8")
        with open(xray_log, "w") as out:
            xray = subprocess.Popen([str(settings.xray_bin), "run", "-c", str(config)],
                                    stdout=out, stderr=subprocess.STDOUT,
                                    start_new_session=True)
        try:
            if not _wait_port(port):
                raise TunnelError(_last_error(xray_log) or "локальный порт не открылся")
            yield f"socks5h://127.0.0.1:{port}", xray_log
        finally:
            _stop(xray)


def _xray_config(entry: dict, port: int) -> dict:
    config = {
        "log": {"loglevel": "info"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"udp": True, "auth": "noauth"}}],
        "outbounds": entry.get("outbounds", []),
    }
    for key in ("dns", "routing", "observatory", "burstObservatory"):
        if entry.get(key):
            config[key] = entry[key]

    # Балансировщику leastPing нужен observatory, без него Xray не стартует.
    balanced = [tag for balancer in entry.get("routing", {}).get("balancers", [])
                for tag in balancer.get("selector", [])]
    if balanced and not {"observatory", "burstObservatory"} & config.keys():
        config["observatory"] = {"subjectSelector": balanced,
                                 "probeUrl": "https://www.gstatic.com/generate_204",
                                 "probeInterval": "10m", "enableConcurrency": True}
    return config


def _why_down(entry: dict, xray_error: str) -> str:
    server = _server(entry)
    if server and not _reachable(*server):
        return f"хост {server[0]}:{server[1]} не отвечает"
    if xray_error:
        return f"туннель не встал: {xray_error}"
    return "хост отвечает, но трафик через туннель не идёт"


def _server(entry: dict) -> tuple[str, int] | None:
    for outbound in entry.get("outbounds", []):
        if outbound.get("protocol") in ("vless", "vmess", "trojan", "shadowsocks"):
            options = outbound.get("settings", {})
            servers = options.get("vnext") or options.get("servers") or []
            if servers:
                return servers[0].get("address"), int(servers[0].get("port"))
    return None


def _reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=6):
            return True
    except OSError:
        return False


def _last_error(xray_log: Path) -> str:
    """Последняя внятная ошибка из лога Xray."""
    try:
        lines = xray_log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for line in reversed(lines[-200:]):
        if XRAY_FAILURE.search(line):
            message = re.sub(r"^\S+ \S+ ", "", line)         # время
            message = re.sub(r"\[\w+\] ", "", message)       # уровень и номер соединения
            message = message.split(" > ")[-1]               # причина — в конце цепочки
            return re.sub(r"^[\w/]+: ", "", message).strip()[:110]
    return ""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_port(port: int, seconds: float = 10) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
    process.wait(timeout=5)


_geo_lock = threading.Lock()
_geo_synced: set[str] = set()


def _sync_geo_files(routing: str) -> None:
    """Правила подписки ссылаются на свои категории (geosite:category-ru-whitelist
    и т. п.), которых нет в стандартных geo-файлах Xray. Откуда брать нужные,
    панель пишет в заголовке routing: happ://routing/onadd/<base64 json>."""
    match = re.search(r"/onadd/([\w=-]+)", routing)
    if not match:
        return
    try:
        info = json.loads(base64.urlsafe_b64decode(match[1] + "=" * (-len(match[1]) % 4)))
    except (ValueError, binascii.Error):
        log("заголовок routing не разобран")
        return

    with _geo_lock:
        for key, name in (("Geoipurl", "geoip.dat"), ("Geositeurl", "geosite.dat")):
            url = info.get(key)
            if not url or url in _geo_synced:
                continue
            target = settings.xray_bin.parent / name
            partial = target.with_suffix(".part")
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "Happ/1.0"})
                with urllib.request.urlopen(request, timeout=120) as resp, \
                        open(partial, "wb") as out:
                    shutil.copyfileobj(resp, out)
            except OSError as exc:
                log(f"{name} не скачан, остаётся стандартный: {exc}")
                continue
            partial.replace(target)
            _geo_synced.add(url)
            log(f"{name} взят из панели")
