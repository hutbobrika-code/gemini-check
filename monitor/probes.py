import json
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from . import http
from .config import ROOT, settings
from .model import BLOCKED, CAPTCHA, DEGRADED, DOWN, OK, Result, overall

SPECS = json.loads((ROOT / "services.json").read_text(encoding="utf-8"))
NAMES = {"gemini": "Gemini"} | {s["id"]: s["name"] for s in SPECS}

IPINFO = "https://ipinfo.io/json"
GEMINI_WEB = "https://gemini.google.com/app"
# ключ специально неверный: если регион разрешён, api отвечает 400 "API key not valid",
# если заблокирован - 403 "User location is not supported". страница gemini в обоих
# случаях отдаёт 200, так что смотреть надо именно api
GEMINI_API = ("https://generativelanguage.googleapis.com/v1beta/models"
              "?key=AIzaSyINVALIDKEYFORPROBE")
GEMINI_UNAVAILABLE = ("not available in your country", "isn't available in your country",
                      "not currently supported", "isn't currently supported",
                      "unsupported_country")


def check_services(point, proxy):
    locate(point, proxy)
    gemini = probe_gemini(proxy)
    if gemini.status == DOWN and not point.exit_ip:
        point.services = {"gemini": gemini}
        point.status = DOWN
        point.note = "канал не отвечает"
        return

    with ThreadPoolExecutor(4) as pool:
        results = pool.map(lambda s: probe_service(proxy, s), SPECS)
        others = {s["id"]: r for s, r in zip(SPECS, results, strict=True)}
    point.services = {"gemini": gemini, **others}
    recheck_failed(point, proxy)
    point.status = overall(point.services)


def url_probe(url):
    # для /check: просто смотрим что ответил сайт
    host = urlparse(url).netloc.lower()

    def probe(point, proxy):
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
            point.status = OK
            point.note = f"увело на {final}" if final != host else ""
        else:
            point.status, point.note = DEGRADED, f"ответ {r.code}"

    return probe


def parse_target(text):
    text = text.strip()
    if not text or any(ch in text for ch in " \n\"'<>"):
        return None
    if "://" not in text:
        text = "https://" + text
    parsed = urlparse(text)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return text
    return None


def locate(point, proxy):
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


def probe_gemini(proxy):
    web = http.fetch(GEMINI_WEB, proxy, follow=True)
    api = http.fetch(GEMINI_API, proxy)
    msg = error_message(api.body)

    if api.code == 403 and "location is not supported" in msg:
        return Result(BLOCKED)
    if any(m in web.body.lower() for m in GEMINI_UNAVAILABLE):
        return Result(BLOCKED)
    if "/sorry/" in web.url:
        return Result(DEGRADED, CAPTCHA)

    api_ok = api.code == 400 and "api key not valid" in msg
    web_ok = web.code == 200 and web.size > 50000
    if api_ok and web_ok:
        result = Result(OK)
    elif api_ok:
        result = Result(DEGRADED, side_note("веб", web.code))
    elif web_ok:
        result = Result(DEGRADED, side_note("API", api.code))
    elif api.code == 0 or web.code == 0:
        return Result(DOWN)
    else:
        return Result(DEGRADED, f"веб {web.code}, API {api.code}")

    if settings.gemini_api_key:
        return ask_model(proxy)
    return result


def ask_model(proxy):
    # если есть настоящий ключ, спрашиваем модель напрямую
    url = ("https://generativelanguage.googleapis.com/v1beta/models/"
           f"{settings.gemini_model}:generateContent?key={settings.gemini_api_key}")
    body = json.dumps({"contents": [{"parts": [{"text": "ping"}]}],
                       "generationConfig": {"maxOutputTokens": 1}})
    r = http.fetch(url, proxy, data=body, headers=["Content-Type: application/json"])
    if r.code in (200, 429):  # 429 это лимит ключа, модель при этом доступна
        return Result(OK)
    if r.code == 403:
        return Result(BLOCKED)
    return Result(DEGRADED, side_note("модель", r.code))


def probe_service(proxy, spec):
    # если у площадки есть api, геоблок смотрим по нему, сайт только дополняет
    if "api" not in spec:
        return probe_endpoint(proxy, spec["web"])
    api = probe_endpoint(proxy, spec["api"])
    if "web" not in spec:
        return api
    web = probe_endpoint(proxy, spec["web"])

    # cloudflare на сайте ругается на curl, а не на адрес, поэтому не считаем
    if api.status == OK and web.status != OK and web.note != "Cloudflare":
        if web.status == BLOCKED:
            return Result(DEGRADED, "веб: регион")
        if web.status == DOWN:
            return Result(DEGRADED, "веб молчит")
        return Result(DEGRADED, f"веб: {web.note}")
    if api.status == DOWN and web.status == OK:
        return Result(DEGRADED, "API молчит")
    return api


def probe_endpoint(proxy, spec):
    r = http.fetch(spec["url"], proxy, timeout=spec.get("timeout", 15),
                   follow=spec.get("follow", True), headers=spec.get("headers", ()))
    body = r.body.lower()
    if r.code == 0:
        return Result(DOWN)
    if "/sorry/" in r.url:
        return Result(DEGRADED, CAPTCHA)
    if r.code in spec.get("blocked_codes", ()):
        return Result(BLOCKED)
    if any(m.lower() in body for m in spec.get("blocked_markers", ())):
        return Result(BLOCKED)
    if r.code in spec.get("ok", (200,)):
        return Result(OK)
    if ("cf-mitigated: challenge" in r.headers or "just a moment" in body
            or ("server: cloudflare" in r.headers and r.code in (403, 503))):
        return Result(DEGRADED, "Cloudflare")
    if 300 <= r.code < 400:
        return Result(DEGRADED, "редиректы")
    return Result(DEGRADED, str(r.code))


def recheck_failed(point, proxy):
    # разовые таймауты бывают часто, поэтому упавшее проверяем второй раз
    failed = [s for s in SPECS
              if point.services[s["id"]].status in (DOWN, DEGRADED)
              and point.services[s["id"]].note != CAPTCHA]
    if not failed:
        return
    time.sleep(2)
    with ThreadPoolExecutor(4) as pool:
        again = list(pool.map(lambda s: probe_service(proxy, s), failed))
    for spec, result in zip(failed, again, strict=True):
        if result.status == OK:
            point.services[spec["id"]] = result


def error_message(body):
    try:
        return json.loads(body)["error"]["message"].lower()
    except (ValueError, KeyError, TypeError):
        return body.lower()


def side_note(side, code):
    if code == 0:
        return f"{side} молчит"
    if 300 <= code < 400:
        return f"{side}: редиректы"
    return f"{side}: {code}"
