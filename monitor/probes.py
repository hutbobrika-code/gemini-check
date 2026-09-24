"""Пробы площадок через готовый прокси."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from . import http
from .config import ROOT, settings
from .model import BLOCKED, CAPTCHA, DEGRADED, DOWN, OK, Point, Result, overall

Probe = Callable[[Point, str], None]

SPECS = json.loads((ROOT / "services.json").read_text(encoding="utf-8"))
NAMES = {"gemini": "Gemini"} | {spec["id"]: spec["name"] for spec in SPECS}

IPINFO = "https://ipinfo.io/json"
GEMINI_WEB = "https://gemini.google.com/app"
# Ключ заведомо неверный. Где Gemini доступен, API отвечает 400 «API key not
# valid», где регион заблокирован — 403 «User location is not supported».
# Веб-страница в обоих случаях отдаёт 200, по ней геоблок не отличить.
GEMINI_API = ("https://generativelanguage.googleapis.com/v1beta/models"
              "?key=AIzaSyINVALIDKEYFORPROBE")
GEMINI_UNAVAILABLE = ("not available in your country", "isn't available in your country",
                      "not currently supported", "isn't currently supported",
                      "unsupported_country")


def check_services(point: Point, proxy: str) -> None:
    """Основная проба: Gemini и все площадки из services.json."""
    locate(point, proxy)
    gemini = probe_gemini(proxy)
    if gemini.status == DOWN and not point.exit_ip:
        point.services = {"gemini": gemini}
        point.status, point.note = DOWN, "канал не отвечает"
        return

    with ThreadPoolExecutor(4) as pool:
        results = pool.map(lambda spec: probe_service(proxy, spec), SPECS)
        others = {spec["id"]: r for spec, r in zip(SPECS, results, strict=True)}
    point.services = {"gemini": gemini, **others}
    _recheck_failures(point, proxy)
    point.status = overall(point.services)


def url_probe(url: str) -> Probe:
    """Проба для /check: смотрим только на то, что ответил сам сайт."""
    host = urlparse(url).netloc.lower()

    def probe(point: Point, proxy: str) -> None:
        locate(point, proxy)
        r = http.fetch(url, proxy, follow=True)
        final = urlparse(r.url).netloc.lower()
        if r.code == 0:
            point.status, point.note = DOWN, "нет ответа"
        elif r.code in (401, 403, 451):
            point.status, point.note = BLOCKED, f"доступ закрыт ({r.code})"
        elif "/sorry/" in r.url:
            point.status, point.note = DEGRADED, CAPTCHA
        elif r.code == 429 or r.code >= 500:
            point.status, point.note = DEGRADED, f"ответ {r.code}"
        elif 300 <= r.code < 400:
            point.status, point.note = DEGRADED, f"редиректы → {final}"
        elif r.code < 300:
            point.status, point.note = OK, f"увело на {final}" if final != host else ""
        else:
            point.status, point.note = DEGRADED, f"ответ {r.code}"

    return probe


def parse_target(text: str) -> str | None:
    """«youtube.com» или «https://site/path» → адрес для пробы."""
    text = text.strip()
    if not text or any(ch in text for ch in " \n\"'<>"):
        return None
    if "://" not in text:
        text = "https://" + text
    parsed = urlparse(text)
    return text if parsed.scheme in ("http", "https") and parsed.netloc else None


def locate(point: Point, proxy: str) -> None:
    """Куда на самом деле выходит трафик."""
    r = http.fetch(IPINFO, proxy, timeout=15)
    point.latency = r.seconds
    if r.code != 200:
        return
    try:
        info = json.loads(r.body)
    except ValueError:
        return
    point.exit_ip = info.get("ip", "")
    point.country = info.get("country", "") or point.country


def probe_gemini(proxy: str) -> Result:
    web = http.fetch(GEMINI_WEB, proxy, follow=True)
    api = http.fetch(GEMINI_API, proxy)
    message = _error_message(api.body)

    if api.code == 403 and "location is not supported" in message:
        return Result(BLOCKED)
    if any(marker in web.body.lower() for marker in GEMINI_UNAVAILABLE):
        return Result(BLOCKED)
    if "/sorry/" in web.url:
        return Result(DEGRADED, CAPTCHA)

    api_ok = api.code == 400 and "api key not valid" in message
    web_ok = web.code == 200 and web.size > 50_000
    if api_ok and web_ok:
        result = Result(OK)
    elif api_ok:
        result = Result(DEGRADED, _side_note("веб", web.code))
    elif web_ok:
        result = Result(DEGRADED, _side_note("API", api.code))
    elif 0 in (api.code, web.code):
        return Result(DOWN)
    else:
        return Result(DEGRADED, f"веб {web.code}, API {api.code}")

    if settings.gemini_api_key:
        return _ask_model(proxy)
    return result


def _ask_model(proxy: str) -> Result:
    """С настоящим ключом вместо косвенных признаков — прямой вопрос модели."""
    url = ("https://generativelanguage.googleapis.com/v1beta/models/"
           f"{settings.gemini_model}:generateContent?key={settings.gemini_api_key}")
    body = json.dumps({"contents": [{"parts": [{"text": "ping"}]}],
                       "generationConfig": {"maxOutputTokens": 1}})
    r = http.fetch(url, proxy, data=body, headers=["Content-Type: application/json"])
    if r.code in (200, 429):       # 429 — модель отвечает, упёрлись в лимит ключа
        return Result(OK)
    if r.code == 403:
        return Result(BLOCKED)
    return Result(DEGRADED, _side_note("модель", r.code))


def probe_service(proxy: str, spec: dict) -> Result:
    """API — главный признак геоблока, сайт лишь уточняет картину."""
    if "api" not in spec:
        return _probe_endpoint(proxy, spec["web"])
    api = _probe_endpoint(proxy, spec["api"])
    if "web" not in spec:
        return api
    web = _probe_endpoint(proxy, spec["web"])

    # Cloudflare на сайте — реакция на curl, а не на адрес: при живом API не в счёт.
    if api.status == OK and web.status != OK and web.note != "Cloudflare":
        if web.status == BLOCKED:
            return Result(DEGRADED, "веб: регион")
        return Result(DEGRADED, "веб молчит" if web.status == DOWN else f"веб: {web.note}")
    if api.status == DOWN and web.status == OK:
        return Result(DEGRADED, "API молчит")
    return api


def _probe_endpoint(proxy: str, spec: dict) -> Result:
    r = http.fetch(spec["url"], proxy, timeout=spec.get("timeout", 15),
                   follow=spec.get("follow", True), headers=spec.get("headers", ()))
    body = r.body.lower()
    if r.code == 0:
        return Result(DOWN)
    if "/sorry/" in r.url:
        return Result(DEGRADED, CAPTCHA)
    if (r.code in spec.get("blocked_codes", ())
            or any(marker.lower() in body for marker in spec.get("blocked_markers", ()))):
        return Result(BLOCKED)
    if r.code in spec.get("ok", (200,)):
        return Result(OK)
    if ("cf-mitigated: challenge" in r.headers or "just a moment" in body
            or ("server: cloudflare" in r.headers and r.code in (403, 503))):
        return Result(DEGRADED, "Cloudflare")
    if 300 <= r.code < 400:
        return Result(DEGRADED, "редиректы")
    return Result(DEGRADED, str(r.code))


def _recheck_failures(point: Point, proxy: str) -> None:
    """Одиночный таймаут — обычно случайность, поэтому неудачу переспрашиваем."""
    failed = [spec for spec in SPECS
              if point.services[spec["id"]].status in (DOWN, DEGRADED)
              and point.services[spec["id"]].note != CAPTCHA]
    if not failed:
        return
    time.sleep(2)
    with ThreadPoolExecutor(4) as pool:
        retried = list(pool.map(lambda spec: probe_service(proxy, spec), failed))
    for spec, result in zip(failed, retried, strict=True):
        if result.status == OK:
            point.services[spec["id"]] = result


def _error_message(body: str) -> str:
    try:
        return json.loads(body)["error"]["message"].lower()
    except (ValueError, KeyError, TypeError):
        return body.lower()


def _side_note(side: str, code: int) -> str:
    if code == 0:
        return f"{side} молчит"
    if 300 <= code < 400:
        return f"{side}: редиректы"
    return f"{side}: {code}"
