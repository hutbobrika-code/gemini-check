"""Прокси proxy-seller: список из кабинета продавца, проверка, автозамена."""

from __future__ import annotations

import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import quote

from . import http, log, now
from .config import settings
from .model import DEGRADED, DOWN, OK, Point
from .probes import IPINFO, Probe

API = "https://proxy-seller.com/personal/api/v1"
KINDS = ("ipv4", "ipv6", "mix", "mix_isp", "isp", "mobile", "resident")

# статус → (тип заявки для продавца, причина для истории, комментарий продавцу)
REPLACE_REASONS = {
    DOWN: ("NOT_WORK", "не отвечал", "Proxy does not respond on http/socks5 ports"),
    DEGRADED: ("CUSTOM", "капча Google", "Google shows abuse captcha for this IP"),
}


def check_all(probe: Probe) -> list[Point]:
    points = load()
    with ThreadPoolExecutor(settings.workers) as pool:
        return list(pool.map(lambda point: check(point, probe), points))


def load() -> list[Point]:
    """Живой список из кабинета продавца, а без ключа — из секрета PROXIES."""
    if settings.ps_api_key:
        points = _from_seller()
        if points:
            return points
        log("продавец не отдал список прокси — беру PROXIES")
    return _from_text(settings.proxies)


def check(point: Point, probe: Probe) -> Point:
    auth = f"{quote(point.login)}:{quote(point.password)}"
    probe(point, f"http://{auth}@{point.name}:{point.http_port}")
    if point.services and point.status in (OK, DEGRADED):
        socks = f"socks5h://{auth}@{point.name}:{point.socks_port}"
        if http.fetch(IPINFO, socks, timeout=15).code != 200:
            point.status, point.note = DEGRADED, f"SOCKS5 :{point.socks_port} не отвечает"
    return point


def request_replacements(points: list[Point], state: dict) -> list[str]:
    """Просит продавца заменить адреса, которые молчат или под капчей Google.

    Денег это не тратит: замена идёт в рамках оплаченной аренды. Заблокированный
    регион не меняем — новый адрес той же страны вёл бы себя так же.
    """
    if not (settings.auto_replace and settings.ps_api_key):
        return []
    requested = state.setdefault("replaced", {})
    reasons = state.setdefault("replace_reason", {})
    cooldown = timedelta(hours=settings.replace_cooldown_hours)
    notes = []

    for point in points:
        broken = point.status == DOWN or (point.status == DEGRADED and point.captcha)
        if not point.ps_id or not broken:
            continue
        last = requested.get(point.name)
        if last and now() - datetime.fromisoformat(last) < cooldown:
            continue
        kind, reason, comment = REPLACE_REASONS[point.status]
        try:
            _call("proxy/replace", {"ids": [int(point.ps_id)], "type": kind, "comment": comment})
            notes.append(f"🔁 {point.name}: продавец принял заявку")
        except (OSError, ValueError, RuntimeError) as exc:
            notes.append(f"⚠️ {point.name}: {exc}")
        requested[point.name] = now().isoformat()
        reasons[point.name] = reason
        log(notes[-1])
    return notes


def detect_replacements(points: list[Point], state: dict) -> list[str]:
    """Замена выполняется не сразу, и узнать о ней можно только по новому IP
    у той же позиции аренды."""
    known = state.setdefault("ips", {})
    notes = []
    for point in points:
        if not point.ps_id:
            continue
        old = known.get(str(point.ps_id))
        if old and old != point.name:
            country = f" ({point.country})" if point.country else ""
            notes.append(f"🔁 {old} → {point.name}{country}")
            state.setdefault("replacement_log", []).append({
                "when": now().isoformat(),
                "old": old,
                "new": point.name,
                "country": point.country,
                "reason": state.get("replace_reason", {}).get(old, "не работал"),
            })
            log(notes[-1])
        known[str(point.ps_id)] = point.name
    return notes


def _from_seller() -> list[Point]:
    points = []
    for kind in KINDS:
        try:
            items = (_call(f"proxy/list/{kind}").get("data") or {}).get("items") or []
        except (OSError, ValueError, RuntimeError) as exc:
            log(f"proxy-seller {kind}: {exc}")
            continue
        for item in items:
            if not item.get("ip") or not item.get("port_http"):
                continue
            http_port = int(item["port_http"])
            points.append(Point(
                "proxy", item["ip"],
                ps_id=item.get("id"),
                login=item.get("login", ""),
                password=item.get("password", ""),
                http_port=http_port,
                socks_port=int(item.get("port_socks") or http_port + 1),
                country=item.get("country") or "",
                date_end=item.get("date_end") or "",
                auto_renew=item.get("auto_renew") == "Y",
            ))
    return points


def _from_text(text: str) -> list[Point]:
    """Строка на прокси: IP:HTTP_PORT@логин@пароль, SOCKS5 — на HTTP_PORT+1."""
    points = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            address, login, password = line.split("@")
            host, port = address.split(":")
            points.append(Point("proxy", host, login=login, password=password,
                                http_port=int(port), socks_port=int(port) + 1))
        except ValueError:
            log(f"строка прокси не разобрана: {line}")
    return points


def _call(path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(f"{API}/{settings.ps_api_key}/{path}", data=data,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as resp:
        answer = json.loads(resp.read())
    if answer.get("errors"):
        raise RuntimeError(str(answer["errors"])[:150])
    return answer
