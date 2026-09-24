import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import quote

from . import http, log, now
from .config import settings
from .model import DEGRADED, DOWN, OK, Point
from .probes import IPINFO

API = "https://proxy-seller.com/personal/api/v1"
KINDS = ("ipv4", "ipv6", "mix", "mix_isp", "isp", "mobile", "resident")

# статус -> тип заявки продавцу, причина для истории, комментарий
REPLACE_REASONS = {
    DOWN: ("NOT_WORK", "не отвечал", "Proxy does not respond on http/socks5 ports"),
    DEGRADED: ("CUSTOM", "капча Google", "Google shows abuse captcha for this IP"),
}


def check_all(probe):
    points = load()
    with ThreadPoolExecutor(settings.workers) as pool:
        return list(pool.map(lambda p: check(p, probe), points))


def load():
    if settings.ps_api_key:
        points = from_seller()
        if points:
            return points
        log("proxy-seller не отдал список, беру из PROXIES")
    return from_text(settings.proxies)


def check(point, probe):
    auth = f"{quote(point.login)}:{quote(point.password)}"
    probe(point, f"http://{auth}@{point.name}:{point.http_port}")
    if point.services and point.status in (OK, DEGRADED):
        socks = f"socks5h://{auth}@{point.name}:{point.socks_port}"
        if http.fetch(IPINFO, socks, timeout=15).code != 200:
            point.status = DEGRADED
            point.note = f"SOCKS5 :{point.socks_port} не отвечает"
    return point


def request_replacements(points, state):
    # замена бесплатная, в рамках оплаченной аренды. меняем только если прокси
    # не отвечает или на нём капча; заблокированную страну не меняем,
    # новый ip из той же страны будет таким же
    if not settings.auto_replace or not settings.ps_api_key:
        return []
    requested = state.setdefault("replaced", {})
    reasons = state.setdefault("replace_reason", {})
    cooldown = timedelta(hours=settings.replace_cooldown_hours)
    notes = []

    for p in points:
        broken = p.status == DOWN or (p.status == DEGRADED and p.captcha)
        if not p.ps_id or not broken:
            continue
        last = requested.get(p.name)
        if last and now() - datetime.fromisoformat(last) < cooldown:
            continue
        kind, reason, comment = REPLACE_REASONS[p.status]
        try:
            call("proxy/replace", {"ids": [int(p.ps_id)], "type": kind, "comment": comment})
            notes.append(f"🔁 {p.name}: продавец принял заявку")
        except (OSError, ValueError, RuntimeError) as e:
            notes.append(f"⚠️ {p.name}: {e}")
        requested[p.name] = now().isoformat()
        reasons[p.name] = reason
        log(notes[-1])
    return notes


def detect_replacements(points, state):
    # продавец меняет адрес не сразу, понять что замена прошла можно только
    # по новому ip у той же позиции (ps_id)
    known = state.setdefault("ips", {})
    notes = []
    for p in points:
        if not p.ps_id:
            continue
        old = known.get(str(p.ps_id))
        if old and old != p.name:
            country = f" ({p.country})" if p.country else ""
            notes.append(f"🔁 {old} → {p.name}{country}")
            state.setdefault("replacement_log", []).append({
                "when": now().isoformat(),
                "old": old,
                "new": p.name,
                "country": p.country,
                "reason": state.get("replace_reason", {}).get(old, "не работал"),
            })
            log(notes[-1])
        known[str(p.ps_id)] = p.name
    return notes


def from_seller():
    points = []
    for kind in KINDS:
        try:
            items = (call(f"proxy/list/{kind}").get("data") or {}).get("items") or []
        except (OSError, ValueError, RuntimeError) as e:
            log(f"proxy-seller {kind}: {e}")
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


def from_text(text):
    # формат: IP:PORT@login@password, socks5 на PORT+1
    points = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            addr, login, password = line.split("@")
            host, port = addr.split(":")
            points.append(Point("proxy", host, login=login, password=password,
                                http_port=int(port), socks_port=int(port) + 1))
        except ValueError:
            log(f"не разобрал строку прокси: {line}")
    return points


def call(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{API}/{settings.ps_api_key}/{path}", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        answer = json.loads(resp.read())
    if answer.get("errors"):
        raise RuntimeError(str(answer["errors"])[:150])
    return answer
