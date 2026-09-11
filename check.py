#!/usr/bin/env python3
"""
Проверка доступности Gemini через узлы подписки QuantoVPN и через внешние прокси.

Для каждого узла подписки поднимается временный Xray с локальным SOCKS-входом
(конфиг берётся живьём из подписки, вместе с её routing/dns — то есть проверяем
ровно то, что получает пользователь), затем через этот туннель делаются пробы:

  1) ipinfo.io/json              — куда реально выходит трафик
  2) gemini.google.com/app       — веб-морда Gemini
  3) generativelanguage.googleapis.com — API; заведомо неверный ключ даёт
     400 "API key not valid" там, где Gemini доступен, и 403 "User location
     is not supported" там, где регион заблокирован. Это самый надёжный
     признак геоблока, веб-страница отдаёт 200 в обоих случаях.

Отчёт уходит в Telegram: при смене состояния — сразу, плюс дайджест в заданные часы.
"""

import concurrent.futures
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
MSK = timezone(timedelta(hours=3))

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")

GEMINI_WEB = "https://gemini.google.com/app"
GEMINI_API = "https://generativelanguage.googleapis.com/v1beta/models?key=AIzaSyINVALIDKEYFORPROBE"
IPINFO = "https://ipinfo.io/json"

# Маркеры страницы «Gemini недоступен в вашей стране»
BLOCK_MARKERS = (
    "not available in your country",
    "isn't available in your country",
    "not currently supported",
    "unsupported_country",
    "isn't currently supported",
)

STATUS_ICON = {"ok": "✅", "blocked": "🚫", "down": "❌", "degraded": "⚠️"}


# ─────────────────────────── конфиг ───────────────────────────

def load_config():
    cfg = {
        "SUB_URL": "",
        "XRAY_BIN": os.path.join(BASE, "bin", "xray"),
        # Список прокси: ключ API продавца, иначе переменная PROXIES, иначе файл.
        "PS_API_KEY": "",
        "PROXIES": "",
        # Настоящий ключ Gemini, если есть: тогда вместо косвенных признаков
        # делается реальный запрос к модели.
        "GEMINI_API_KEY": "",
        "GEMINI_MODEL": "gemini-2.0-flash",
        # За сколько дней до конца аренды прокси предупреждать.
        "EXPIRY_WARN_DAYS": "3",
        # Автозамена битых адресов и пауза между попытками по одному адресу.
        "AUTO_REPLACE": "1",
        "REPLACE_COOLDOWN_HOURS": "6",
        "PROXIES_FILE": os.path.join(BASE, "proxies.txt"),
        "STATE_FILE": os.path.join(BASE, "state", "state.json"),
        "TG_TOKEN": "",
        "TG_CHAT_IDS": "",
        "DIGEST_HOURS": "10,22",
        "SOCKS_PORT_BASE": "10900",
        "TIMEOUT": "25",
        "WORKERS": "5",
        "CHECK_PROXIES": "1",
        "CHECK_NODES": "1",
    }
    path = os.path.join(BASE, "config.env")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip('"').strip("'")
    for k in list(cfg):
        if os.environ.get(k):
            cfg[k] = os.environ[k]
    return cfg


CFG = load_config()
TIMEOUT = int(CFG["TIMEOUT"])


def log(msg):
    print(f"[{datetime.now(MSK):%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


# ─────────────────────────── пробы ───────────────────────────

def curl(url, proxy=None, timeout=TIMEOUT, body_bytes=4096, follow=False):
    """Возвращает (код, тело, размер, секунды, конечный_url). Код 0 — не дозвонились."""
    out = tempfile.NamedTemporaryFile(delete=False)
    out.close()
    hdr = tempfile.NamedTemporaryFile(delete=False)
    hdr.close()
    cmd = ["curl", "-sS", "-m", str(timeout), "-A", UA, "-o", out.name,
           "-D", hdr.name,
           "-w", "%{http_code} %{size_download} %{time_total} %{url_effective}"]
    if follow:
        cmd += ["-L", "--max-redirs", "5"]
    if proxy:
        cmd += ["-x", proxy]
    cmd.append(url)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        parts = res.stdout.strip().split()
        code = int(parts[0]) if parts else 0
        size = int(parts[1]) if len(parts) > 1 else 0
        secs = float(parts[2]) if len(parts) > 2 else 0.0
        final = parts[3] if len(parts) > 3 else url
        if 300 <= code < 400:
            # curl остановился на редиректе (обычно упёрся в --max-redirs):
            # url_effective тут бесполезен, настоящая цель — в последнем Location.
            final = last_location(hdr.name) or final
        with open(out.name, "rb") as fh:
            body = fh.read(body_bytes).decode("utf-8", "replace")
        return code, body, size, secs, final
    except Exception as exc:  # noqa: BLE001
        log(f"curl {url} через {proxy or 'direct'}: {exc}")
        return 0, "", 0, 0.0, url
    finally:
        for path in (out.name, hdr.name):
            try:
                os.unlink(path)
            except OSError:
                pass


def last_location(header_file):
    """Куда в итоге ведёт цепочка редиректов.

    Если в ней хоть раз мелькнул /sorry/ — возвращаем именно его: это страница
    «докажите, что вы не робот», и она объясняет петлю целиком. Иначе цикл
    выглядел бы как безобидный редирект сайта на самого себя.
    """
    try:
        with open(header_file, encoding="utf-8", errors="replace") as fh:
            found = [ln.split(":", 1)[1].strip()
                     for ln in fh if ln.lower().startswith("location:")]
    except OSError:
        return ""
    for url in found:
        if "/sorry/" in url:
            return url
    return found[-1] if found else ""


def probe_gemini(proxy):
    """Полная проба через уже готовый прокси. Возвращает dict с полями отчёта."""
    r = {"exit_ip": None, "country": None, "org": None,
         "web_code": 0, "api_code": 0, "api_msg": "", "latency": 0.0}

    code, body, _, secs, _ = curl(IPINFO, proxy, timeout=15)
    r["latency"] = secs
    if code == 200:
        try:
            info = json.loads(body)
            r["exit_ip"] = info.get("ip")
            r["country"] = info.get("country")
            r["org"] = info.get("org")
        except json.JSONDecodeError:
            pass

    # По редиректам идём: без -L страница-заглушка выглядела бы просто как 302,
    # и было бы не видно, ведёт она на вход в аккаунт или на капчу Google.
    code, body, size, _, final = curl(GEMINI_WEB, proxy, follow=True)
    r["web_code"] = code
    r["web_size"] = size
    r["web_final"] = final
    low = body.lower()
    r["web_blocked_marker"] = any(m in low for m in BLOCK_MARKERS)

    code, body, _, _, _ = curl(GEMINI_API, proxy)
    r["api_code"] = code
    m = re.search(r'"message"\s*:\s*"([^"]+)"', body)
    r["api_msg"] = m.group(1) if m else ""

    r["status"], r["note"] = classify(r)

    # Косвенные признаки говорят «регион разрешён и адрес не забанен».
    # Настоящий ответ модели это доказывает, но нужен рабочий ключ.
    key = CFG["GEMINI_API_KEY"].strip()
    if key and r["status"] in ("ok", "degraded"):
        real_code, real_msg = real_gemini_call(proxy, key)
        r["real_code"] = real_code
        if real_code == 200:
            r["status"], r["note"] = "ok", ""
        elif real_code == 429:
            r["status"], r["note"] = "ok", "модель отвечает, но упёрлись в лимит ключа"
        elif real_code:
            r["status"] = "blocked" if real_code == 403 else "degraded"
            r["note"] = f"модель не ответила: {real_code} {real_msg[:70]}"
    return r


def probe_url(proxy, url):
    """Проверка произвольного адреса через готовый прокси.

    В отличие от пробы Gemini тут нет косвенных признаков геоблока — смотрим
    на то, что отдал сам сайт: ответил ли, чем ответил и куда увёл.
    """
    r = {"exit_ip": None, "country": None, "latency": 0.0}
    code, _, size, secs, final = curl(url, proxy, follow=True)
    r["latency"] = secs
    r["web_code"] = code
    r["web_size"] = size
    r["web_final"] = final

    host = urllib.parse.urlparse(url).netloc.lower()
    final_host = urllib.parse.urlparse(final).netloc.lower()

    if code == 0:
        r["status"], r["note"] = "down", "нет ответа"
    elif code in (401, 403, 451):
        r["status"], r["note"] = "blocked", f"доступ запрещён ({code})"
    elif "/sorry/" in final:
        r["status"], r["note"] = "degraded", "капча Google — адрес подозрительный"
    elif 500 <= code < 600:
        r["status"], r["note"] = "degraded", f"ошибка сервера ({code})"
    elif code == 429:
        r["status"], r["note"] = "degraded", "слишком много запросов (429)"
    elif 300 <= code < 400:
        r["status"], r["note"] = "degraded", f"редирект без конца → {final_host or final[:40]}"
    elif 200 <= code < 300:
        if final_host and host and final_host != host:
            r["status"], r["note"] = "ok", f"открылось, но увело на {final_host}"
        else:
            r["status"], r["note"] = "ok", ""
    else:
        r["status"], r["note"] = "degraded", f"ответ {code}"
    return r


def normalize_target(text):
    """Из «youtube.com» или «https://site/path» делает корректный адрес пробы."""
    text = (text or "").strip()
    if not text:
        return None
    if "://" not in text:
        text = "https://" + text
    parsed = urllib.parse.urlparse(text)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    if any(ch in text for ch in (" ", "\n", '"', "'")):
        return None
    return text


def real_gemini_call(proxy, key):
    """Просит модель ответить одним словом. 200 — Gemini через эту точку работает."""
    body = ('{"contents":[{"parts":[{"text":"ping"}]}],'
            '"generationConfig":{"maxOutputTokens":1}}')
    url = ("https://generativelanguage.googleapis.com/v1beta/models/"
           f"{CFG['GEMINI_MODEL']}:generateContent?key={key}")
    out = tempfile.NamedTemporaryFile(delete=False)
    out.close()
    cmd = ["curl", "-sS", "-m", str(TIMEOUT), "-o", out.name,
           "-w", "%{http_code}", "-H", "Content-Type: application/json",
           "-d", body]
    if proxy:
        cmd += ["-x", proxy]
    cmd.append(url)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT + 10)
        code = int(res.stdout.strip() or 0)
        with open(out.name, encoding="utf-8", errors="replace") as fh:
            text = fh.read(1000)
        m = re.search(r'"message"\s*:\s*"([^"]+)"', text)
        return code, (m.group(1) if m else "")
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)
    finally:
        try:
            os.unlink(out.name)
        except OSError:
            pass


def classify(r):
    api, msg = r["api_code"], r["api_msg"].lower()
    web = r["web_code"]

    if api == 0 and web == 0 and r["exit_ip"] is None:
        return "down", "канал не отвечает"

    if api == 403 and ("location is not supported" in msg or "user location" in msg):
        return "blocked", "Google блокирует регион (403 user location)"
    if r["web_blocked_marker"]:
        return "blocked", "страница Gemini: регион не поддерживается"

    final = r.get("web_final") or ""
    if "/sorry/" in final:
        # Так Google отвечает на адреса, которые считает подозрительными:
        # выдаёт GOOGLE_ABUSE_EXEMPTION, не принимает его и шлёт на капчу снова.
        return "degraded", "Google требует капчу — адрес помечен как подозрительный"

    api_ok = api == 400 and "api key not valid" in msg
    web_ok = web == 200 and r.get("web_size", 0) > 50_000

    if api_ok and web_ok:
        return "ok", ""
    if api_ok and not web_ok:
        host = urllib.parse.urlparse(final).netloc
        if 300 <= web < 400:
            target = host or final[:40] or "неизвестно куда"
            return "degraded", f"API доступен, но веб гоняет по редиректам → {target}"
        return "degraded", f"API доступен, веб отдал {web or 'таймаут'}"
    if web_ok and not api_ok:
        return "degraded", f"веб открывается, API отдал {api or 'таймаут'}"
    if api == 0 or web == 0:
        return "down", "таймаут на запросах к Google"
    return "degraded", f"неожиданный ответ: web={web}, api={api} {r['api_msg'][:60]}"


# ─────────────────────────── узлы подписки ───────────────────────────

def fetch_subscription(url):
    req = urllib.request.Request(url, headers={"user-agent": "Happ/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, list):
        raise ValueError("подписка вернула не список конфигов (клиент не распознан?)")
    return data


def free_port(start):
    for port in range(start, start + 200):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("нет свободных портов под SOCKS")


def wait_port(port, deadline=10.0):
    end = time.time() + deadline
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def node_address(entry):
    for ob in entry.get("outbounds", []):
        if ob.get("protocol") in ("vless", "vmess", "trojan", "shadowsocks"):
            st = ob.get("settings", {})
            vnext = st.get("vnext") or st.get("servers") or []
            if vnext:
                return f"{vnext[0].get('address')}:{vnext[0].get('port')}"
    return "?"


def tcp_reachable(addr, timeout=6.0):
    """Отдельная проба самого хоста: отличает мёртвый сервер от живого с битым туннелем."""
    host, _, port = addr.rpartition(":")
    if not host or not port.isdigit():
        return None
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def xray_error(log_path):
    """Последняя осмысленная ошибка из лога Xray — она объясняет, почему туннель не встал."""
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return ""
    for line in reversed(lines[-200:]):
        if re.search(r"failed|rejected|refused|timeout|bad status code|unauthenticated", line, re.I):
            msg = re.sub(r"^\S+ \S+ ", "", line)            # метка времени
            msg = re.sub(r"\[\w+\] ", "", msg)              # уровень и id соединения
            msg = msg.split(" > ")[-1]                      # у Xray причина — в хвосте цепочки
            msg = re.sub(r"^[\w/]+: ", "", msg)             # путь пакета
            return msg.strip()[:110]
    return ""


def check_node(entry, port_base, probe=None):
    name = entry.get("remarks", "без имени")
    result = {"kind": "node", "name": name, "addr": node_address(entry)}
    port = free_port(port_base)

    result["tcp"] = tcp_reachable(result["addr"])

    cfg = {
        "log": {"loglevel": "info"},
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": port,
            "protocol": "socks",
            "settings": {"udp": True, "auth": "noauth"},
        }],
        "outbounds": entry.get("outbounds", []),
    }
    if entry.get("dns"):
        cfg["dns"] = entry["dns"]
    if entry.get("routing"):
        # правила подписки сохраняем: проверяем то, что видит реальный клиент
        cfg["routing"] = entry["routing"]

    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(cfg, tmp, ensure_ascii=False)
    tmp.close()

    xlog = tmp.name + ".log"
    proc = None
    try:
        with open(xlog, "w", encoding="utf-8") as lf:
            proc = subprocess.Popen(
                [CFG["XRAY_BIN"], "run", "-c", tmp.name],
                stdout=lf, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        if not wait_port(port):
            result.update(status="down", note="Xray не поднял локальный порт")
            return result
        result.update((probe or probe_gemini)(f"socks5h://127.0.0.1:{port}"))
        if result["status"] == "down":
            result["note"] = describe_failure(result, xray_error(xlog))
    except Exception as exc:  # noqa: BLE001
        result.update(status="down", note=f"ошибка запуска Xray: {exc}")
    finally:
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                proc.kill()
            proc.wait(timeout=5)
        for path in (tmp.name, xlog):
            try:
                os.unlink(path)
            except OSError:
                pass
    return result


def describe_failure(result, xerr):
    if result.get("tcp") is False:
        return f"хост {result['addr']} не отвечает"
    if xerr:
        return f"туннель не встал: {xerr}"
    return "хост отвечает, но трафик через туннель не идёт"


# ─────────────────────────── прокси из orders.txt ───────────────────────────

PS_TYPES = ("ipv4", "ipv6", "mix", "mix_isp", "isp", "mobile", "resident")


def proxies_from_seller(api_key):
    """Живой список из личного кабинета proxy-seller.

    Лучше ручного списка тем, что сам подхватывает новые адреса и видит срок
    аренды — о протухающих прокси можно предупредить заранее.
    """
    items = []
    for kind in PS_TYPES:
        url = f"https://proxy-seller.com/personal/api/v1/{api_key}/proxy/list/{kind}"
        try:
            with urllib.request.urlopen(url, timeout=25) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            log(f"proxy-seller {kind}: {exc}")
            continue
        if data.get("errors"):
            log(f"proxy-seller {kind}: {data['errors']}")
            continue
        for p in (data.get("data") or {}).get("items") or []:
            http_port = p.get("port_http")
            if not p.get("ip") or not http_port:
                continue
            items.append({
                "ps_id": p.get("id"),
                "host": p["ip"],
                "http_port": int(http_port),
                "socks_port": int(p.get("port_socks") or int(http_port) + 1),
                "user": p.get("login", ""),
                "password": p.get("password", ""),
                "country": p.get("country"),
                "auto_renew": p.get("auto_renew"),
                "date_end": p.get("date_end"),
                "kind_ps": kind,
            })
    log(f"proxy-seller отдал {len(items)} прокси")
    return items


def proxies_source():
    """Список прокси: сначала API продавца, иначе секрет PROXIES, иначе файл."""
    if CFG["PROXIES"].strip():
        return CFG["PROXIES"].splitlines()
    path = CFG["PROXIES_FILE"]
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read().splitlines()
    return []


def proxy_list():
    if CFG["PS_API_KEY"].strip():
        items = proxies_from_seller(CFG["PS_API_KEY"].strip())
        if items:
            return items
        log("API продавца ничего не вернул — беру запасной список")
    return parse_proxies(proxies_source())


def replace_proxy(api_key, ps_id, reason, comment):
    """Просит продавца выдать взамен другой IP. Денег не тратит — это замена
    в рамках уже оплаченной аренды, а не новая покупка.

    Причина обязательна: без поля type продавец отвечает отказом со списком
    допустимых значений (NOT_WORK / INCORRECT_LOCATION / CANT_CHANGE_NETWORK /
    LOW_SPEED / CUSTOM).
    """
    url = f"https://proxy-seller.com/personal/api/v1/{api_key}/proxy/replace"
    body = json.dumps({"ids": [int(ps_id)], "type": reason,
                       "comment": comment}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:120]
    if data.get("errors"):
        return False, str(data["errors"])[:150]
    return True, "продавец принял заявку на замену"


def auto_replace(proxies, state):
    """Меняет адреса, которые не работают или на которых Google требует капчу.

    Заблокированный регион не меняем: там дело не в адресе, а в стране —
    новый IP того же региона будет вести себя так же.
    """
    key = CFG["PS_API_KEY"].strip()
    if CFG["AUTO_REPLACE"] != "1" or not key:
        return []

    done = state.setdefault("replaced", {})
    cooldown = int(CFG["REPLACE_COOLDOWN_HOURS"]) * 3600
    now = datetime.now(MSK)
    notes = []

    for r in proxies:
        if not r.get("ps_id"):
            continue
        note = (r.get("note") or "").lower()
        broken = r.get("status") == "down" or (
            r.get("status") == "degraded" and "капч" in note)
        if not broken:
            continue

        last = done.get(r["name"])
        if last:
            try:
                if (now - datetime.fromisoformat(last)).total_seconds() < cooldown:
                    continue  # уже меняли недавно — ждём, а не долбим продавца
            except ValueError:
                pass

        if r.get("status") == "down":
            reason = "NOT_WORK"
            comment = "Proxy does not respond on http/socks5 ports"
        else:
            reason = "CUSTOM"
            comment = "Google shows abuse captcha for this IP, Gemini web is unusable"

        ok, msg = replace_proxy(key, r["ps_id"], reason, comment)
        done[r["name"]] = now.isoformat()
        # Причину запоминаем к моменту, когда продавец выдаст новый адрес:
        # тогда в истории будет видно, из-за чего адрес поменяли.
        state.setdefault("replace_reason", {})[r["name"]] = (
            "не отвечал" if reason == "NOT_WORK" else "капча Google")
        icon = "🔁" if ok else "⚠️"
        notes.append(f"{icon} {r['name']}: {msg}")
        log(f"замена {r['name']}: {msg}")

    return notes


def render_replacements(state, limit=20):
    """История замен: какой адрес на какой поменяли и когда."""
    log_entries = state.get("replacement_log") or []
    lines = ["<b>🔁 Замены адресов</b>", ""]
    if not log_entries:
        lines.append("Замен не было — все адреса те же, что выдал продавец.")
    else:
        for e in log_entries[-limit:]:
            when = e.get("when", "")[:16].replace("T", " ")
            country = f" · {esc(e['country'])}" if e.get("country") else ""
            lines.append(f"{esc(e.get('old'))} → <b>{esc(e.get('new'))}</b>{country}")
            lines.append(f"    {esc(when)} МСК · причина: {esc(e.get('reason', '—'))}")
        lines.append("")
        lines.append(f"Всего замен: {len(log_entries)}")

    pending = state.get("replaced") or {}
    if pending:
        lines.append("")
        lines.append("<i>Последние заявки продавцу:</i>")
        for ip, when in list(pending.items())[-10:]:
            lines.append(f"{esc(ip)} — {esc(when[:16].replace('T', ' '))} МСК")
    return "\n".join(lines)


def detect_new_ips(proxies, state):
    """Ловит момент, когда продавец выдал другой адрес взамен старого.

    Заявку на замену мы отправляем сами, но выполняется она не мгновенно, и
    узнать о ней можно только по смене IP у той же позиции аренды (ps_id).
    """
    known = state.setdefault("ips", {})
    notes = []
    for r in proxies:
        pid = str(r.get("ps_id") or "")
        if not pid:
            continue
        was = known.get(pid)
        if was and was != r["name"]:
            notes.append(f"🔁 {was} заменён на {r['name']}"
                         + (f" ({r['country']})" if r.get("country") else ""))
            log(f"замена выполнена: {was} → {r['name']}")
            state.setdefault("replacement_log", []).append({
                "when": datetime.now(MSK).isoformat(),
                "old": was, "new": r["name"],
                "country": r.get("country") or r.get("country_ps"),
                "reason": (state.get("replace_reason") or {}).get(was, "не работал"),
            })
        known[pid] = r["name"]
    return notes


def days_left(date_end):
    """Сколько дней осталось до конца аренды. Формат продавца — ДД.ММ.ГГГГ."""
    if not date_end:
        return None
    for fmt in ("%d.%m.%Y", "%Y-%m-%d", "%d.%m.%Y %H:%M:%S"):
        try:
            end = datetime.strptime(date_end.strip(), fmt).replace(tzinfo=MSK)
            return (end - datetime.now(MSK)).days
        except ValueError:
            continue
    return None


def parse_proxies(lines):
    """Формат строки: IP:HTTP_PORT@user@pass. SOCKS5 живёт на HTTP_PORT+1."""
    items = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("@")
        if len(parts) != 3:
            log(f"пропущена строка прокси (неизвестный формат): {line}")
            continue
        hostport, user, password = parts
        host, _, port = hostport.partition(":")
        if not port.isdigit():
            log(f"пропущена строка прокси (нет порта): {line}")
            continue
        items.append({"host": host, "http_port": int(port),
                      "socks_port": int(port) + 1,
                      "user": user, "password": password})
    return items


def check_proxy(p, probe=None):
    auth = f"{urllib.parse.quote(p['user'])}:{urllib.parse.quote(p['password'])}"
    http_proxy = f"http://{auth}@{p['host']}:{p['http_port']}"
    socks_proxy = f"socks5h://{auth}@{p['host']}:{p['socks_port']}"

    result = {"kind": "proxy", "name": p["host"], "ps_id": p.get("ps_id"),
              "addr": f"{p['host']}:{p['http_port']}/{p['socks_port']}",
              "creds": {"user": p["user"], "password": p["password"],
                        "http_port": p["http_port"], "socks_port": p["socks_port"]}}
    result.update((probe or probe_gemini)(http_proxy))
    if p.get("country"):
        result.setdefault("country_ps", p["country"])

    result["date_end"] = p.get("date_end")
    result["days_left"] = days_left(p.get("date_end"))
    result["auto_renew"] = p.get("auto_renew")

    code, _, _, _, _ = curl(IPINFO, socks_proxy, timeout=15)
    result["socks_ok"] = code == 200
    if not result["socks_ok"] and result["status"] == "ok":
        result["status"] = "degraded"
        result["note"] = f"HTTP {p['http_port']} работает, SOCKS5 {p['socks_port']} — нет"
    return result


# ─────────────────────────── отчёт ───────────────────────────

def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def plural_days(n):
    n = abs(n)
    if 11 <= n % 100 <= 14:
        return f"{n} дней"
    return f"{n} " + {1: "день", 2: "дня", 3: "дня", 4: "дня"}.get(n % 10, "дней")


def rent_line(r):
    """Строка про аренду: до какого числа и сколько осталось."""
    if not r.get("date_end"):
        return ""
    left = r.get("days_left")
    end = esc(r["date_end"].rsplit(".", 1)[0])  # день и месяц, год лишний
    renew = r.get("auto_renew") == "Y"

    if left is None:
        text = f"аренда до {end}"
    elif left < 0:
        text = f"аренда кончилась {end}"
    elif left == 0:
        text = f"аренда до {end} — сегодня последний день"
    else:
        text = f"аренда до {end}, осталось {plural_days(left)}"

    if renew:
        return f"🔄 {text} · автопродление включено"
    icon = "⏳" if left is not None and left <= int(CFG["EXPIRY_WARN_DAYS"]) else "📅"
    return f"{icon} {text}"


def render(nodes, proxies, digest, title=None):
    now = datetime.now(MSK)
    head = title or ("📊 Сводка Gemini" if digest else "🔔 Изменение доступности Gemini")
    lines = [f"<b>{head}</b> · {now:%d.%m %H:%M} МСК", ""]

    def block(title, rows):
        if not rows:
            return
        ok = sum(1 for r in rows if r.get("status") == "ok")
        lines.append(f"<b>{title}</b> — Gemini открывается на {ok} из {len(rows)}")
        for r in rows:
            icon = STATUS_ICON.get(r.get("status"), "❔")
            geo = ""
            if r.get("country"):
                geo = f" · {esc(r['country'])} {esc(r.get('exit_ip') or '')}"
            tail = ""
            if r.get("status") == "ok":
                tail = f" · {r.get('latency', 0):.1f}s"
            elif r.get("note"):
                tail = f" · {esc(r['note'])}"
            lines.append(f"{icon} {esc(r['name'])}{geo}{tail}")
            rent = rent_line(r)
            if rent:
                lines.append(f"    {rent}")
        lines.append("")

    block("Узлы подписки", nodes)
    block("Прокси", proxies)

    total = nodes + proxies
    bad = [r for r in total if r.get("status") != "ok"]
    if bad:
        lines.append(f"Проблемных точек: {len(bad)} из {len(total)}")
    else:
        lines.append("Все точки отдают Gemini.")
    return "\n".join(lines).strip()


def tg_api(method, **params):
    token = CFG["TG_TOKEN"]
    if not token:
        raise RuntimeError("не задан TG_TOKEN")
    # При длинном опросе Telegram держит соединение сам — ждать надо дольше,
    # чем он обещает молчать, иначе рвём связь на каждом пустом опросе.
    wait = int(params.get("timeout") or 0) + 20
    data = urllib.parse.urlencode(
        {k: v for k, v in params.items() if v is not None}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}", data=data)
    with urllib.request.urlopen(req, timeout=max(wait, 25)) as resp:
        return json.loads(resp.read().decode("utf-8"))


STATUS_WORD = {
    "ok": "работает",
    "down": "не работает",
    "blocked": "заблокирован",
    "degraded": "работает частично",
}


def render_alert(rows, prev):
    """Сообщение о поломке: сначала что именно слетело, потом общий счёт."""
    now = datetime.now(MSK)
    changed = [r for r in rows if prev.get(f"{r['kind']}:{r['name']}") != r.get("status")]
    broken = [r for r in changed if r.get("status") != "ok"]

    head = "🔴 Точка слетела" if broken else "🟢 Восстановление"
    if len(changed) > 1:
        head = "🔴 Изменения" if broken else "🟢 Восстановление"
    lines = [f"<b>{head}</b> · {now:%d.%m %H:%M} МСК", ""]

    for r in changed:
        was = prev.get(f"{r['kind']}:{r['name']}")
        icon = STATUS_ICON.get(r.get("status"), "❔")
        became = STATUS_WORD.get(r.get("status"), r.get("status"))
        prefix = "новая точка" if was is None else f"было «{STATUS_WORD.get(was, was)}»"
        lines.append(f"{icon} <b>{esc(r['name'])}</b> — {prefix}, стало «{became}»")
        if r.get("note"):
            lines.append(f"    {esc(r['note'])}")
        if r.get("exit_ip"):
            lines.append(f"    выход: {esc(r.get('country') or '?')} {esc(r['exit_ip'])}")

    for kind, title in (("node", "Узлы подписки"), ("proxy", "Прокси")):
        group = [r for r in rows if r["kind"] == kind]
        if group:
            ok = sum(1 for r in group if r.get("status") == "ok")
            lines.append("")
            lines.append(f"{title}: Gemini открывается на {ok} из {len(group)}")
    return "\n".join(lines).strip()


def send_telegram(text, chat_ids=None, reply_to=None):
    token = CFG["TG_TOKEN"]
    chats = chat_ids if chat_ids is not None else [
        c.strip() for c in CFG["TG_CHAT_IDS"].split(",") if c.strip()]
    if not token or not chats:
        log("Telegram не настроен (TG_TOKEN/TG_CHAT_IDS) — отчёт только в лог")
        return
    for chunk_start in range(0, len(text), 3800):
        chunk = text[chunk_start:chunk_start + 3800]
        for chat in chats:
            answer_to = reply_to if chunk_start == 0 else None
            try:
                tg_api("sendMessage", chat_id=chat, text=chunk,
                       parse_mode="HTML", disable_web_page_preview="true",
                       reply_to_message_id=answer_to)
                log(f"отчёт отправлен в чат {chat}")
                continue
            except Exception as exc:  # noqa: BLE001
                detail = tg_error(exc)
                log(f"не удалось отправить в чат {chat}: {detail}")

            # Ответ на сообщение отваливается, если его успели удалить или оно
            # из другой ветки. Сам отчёт при этом нужен — шлём его без ответа.
            if not answer_to:
                continue
            try:
                tg_api("sendMessage", chat_id=chat, text=chunk,
                       parse_mode="HTML", disable_web_page_preview="true")
                log(f"отчёт отправлен в чат {chat} (без ответа на сообщение)")
            except Exception as exc:  # noqa: BLE001
                log(f"повтор без ответа тоже не прошёл: {tg_error(exc)}")


def send_document(filename, content, caption="", chat_ids=None):
    """Отправляет текстовый файл в чат. Данные прокси удобнее файлом:
    в сообщении их не выделить одним куском и не скормить другому инструменту."""
    token = CFG["TG_TOKEN"]
    chats = chat_ids if chat_ids is not None else [
        c.strip() for c in CFG["TG_CHAT_IDS"].split(",") if c.strip()]
    if not token or not chats:
        return
    boundary = "----geminicheck" + str(int(time.time() * 1000))
    for chat in chats:
        parts = []
        for name, value in (("chat_id", chat), ("caption", caption[:1000]),
                            ("parse_mode", "HTML")):
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"'
                f'\r\n\r\n{value}\r\n'.encode("utf-8"))
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="document";'
            f' filename="{filename}"\r\nContent-Type: text/plain; charset=utf-8'
            f'\r\n\r\n'.encode("utf-8"))
        parts.append(content.encode("utf-8"))
        parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
        body = b"".join(parts)
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendDocument", data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                resp.read()
            log(f"файл {filename} отправлен в чат {chat}")
        except Exception as exc:  # noqa: BLE001
            log(f"файл не ушёл в чат {chat}: {tg_error(exc)}")


def proxy_file_body(proxies):
    """Готовый к вставке список: строка на прокси, в конце — статус проверки."""
    now = datetime.now(MSK)
    lines = [
        f"# Прокси и результат проверки Gemini · {now:%d.%m.%Y %H:%M} МСК",
        "# Формат: протокол://логин:пароль@адрес:порт",
        "",
    ]
    for r in proxies:
        creds = r.get("creds")
        head = f"# {r['name']} — {STATUS_WORD.get(r.get('status'), r.get('status'))}"
        details = []
        if r.get("country"):
            details.append(r["country"])
        if r.get("note"):
            details.append(r["note"])
        if r.get("date_end"):
            left = r.get("days_left")
            renew = " автопродление" if r.get("auto_renew") == "Y" else ""
            details.append(f"аренда до {r['date_end']}"
                           + (f", осталось {plural_days(left)}" if left is not None else "")
                           + renew)
        if details:
            head += " (" + "; ".join(details) + ")"
        lines.append(head)
        if creds:
            lines.append(f"http://{creds['user']}:{creds['password']}"
                         f"@{r['name']}:{creds['http_port']}")
            lines.append(f"socks5://{creds['user']}:{creds['password']}"
                         f"@{r['name']}:{creds['socks_port']}")
        lines.append("")

    working = [r for r in proxies if r.get("status") == "ok"]
    lines.append(f"# Итого рабочих: {len(working)} из {len(proxies)}")
    return "\n".join(lines)


def tg_error(exc):
    """У HTTPError полезное лежит в теле ответа, а не в тексте исключения."""
    body = ""
    if hasattr(exc, "read"):
        try:
            body = exc.read().decode("utf-8", "replace")[:300]
        except Exception:  # noqa: BLE001
            body = ""
    m = re.search(r'"description"\s*:\s*"([^"]+)"', body)
    return m.group(1) if m else f"{exc} {body}".strip()


# ─────────────────────────── состояние ───────────────────────────

def load_state():
    path = CFG["STATE_FILE"]
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def save_state(state):
    path = CFG["STATE_FILE"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=1)
    shutil.move(tmp, path)


# ─────────────────────────── main ───────────────────────────

def run_all(probe=None):
    """Прогоняет все проверки и возвращает (узлы, прокси).

    probe — чем именно проверять точку. По умолчанию Gemini; команда /check
    подставляет сюда пробу произвольного адреса.
    """
    port_base = int(CFG["SOCKS_PORT_BASE"])
    workers = int(CFG["WORKERS"])
    nodes, proxies = [], []

    if CFG["CHECK_NODES"] == "1" and CFG["SUB_URL"]:
        try:
            entries = fetch_subscription(CFG["SUB_URL"])
            log(f"подписка: {len(entries)} записей")
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(check_node, e, port_base + i * 5, probe)
                           for i, e in enumerate(entries)]
                nodes = [f.result() for f in futures]
        except Exception as exc:  # noqa: BLE001
            log(f"подписка недоступна: {exc}")
            nodes = [{"kind": "node", "name": "подписка целиком", "status": "down",
                      "note": f"не удалось получить список узлов: {exc}"}]

    if CFG["CHECK_PROXIES"] == "1":
        plist = proxy_list()
        log(f"прокси: {len(plist)} штук")
        if plist:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                proxies = list(pool.map(lambda p: check_proxy(p, probe), plist))

    for r in nodes + proxies:
        log(f"{r.get('status'):9} {r['name']} — web={r.get('web_code')} "
            f"api={r.get('api_code')} exit={r.get('exit_ip')} {r.get('note', '')}")

    return nodes, proxies


def main():
    force = "--force" in sys.argv or "--digest" in sys.argv
    quiet = "--no-send" in sys.argv

    nodes, proxies = run_all()

    state = load_state()
    current = {f"{r['kind']}:{r['name']}": r.get("status") for r in nodes + proxies}
    changed = [k for k, v in current.items() if state.get("statuses", {}).get(k) != v]

    hours = {int(h) for h in re.findall(r"\d+", CFG["DIGEST_HOURS"])}
    now = datetime.now(MSK)
    last_digest = state.get("last_digest", "")
    digest_slot = f"{now:%Y-%m-%d}-{now.hour}"
    digest_due = now.hour in hours and last_digest != digest_slot

    if force or digest_due:
        text = render(nodes, proxies, digest=True)
    elif changed:
        # При поломке важно видеть сразу, что именно слетело, а не искать
        # изменившуюся строку глазами в списке из полутора десятков точек.
        text = render_alert(nodes + proxies, state.get("statuses", {}))
    else:
        text = None

    if text:
        log("отчёт:\n" + text)
        if not quiet:
            send_telegram(text)
            if proxies:
                send_document(f"proxy-{now:%d.%m-%H%M}.txt", proxy_file_body(proxies),
                              caption="Список прокси с результатом проверки")
        if digest_due or force:
            state["last_digest"] = digest_slot
    else:
        log("состояние не изменилось, дайджест не по расписанию — молчим")

    state["statuses"] = current
    state["updated_at"] = now.isoformat()
    save_state(state)


if __name__ == "__main__":
    main()
