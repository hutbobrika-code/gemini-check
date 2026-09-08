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
        # Список прокси: либо переменная PROXIES (многострочная, из секретов), либо файл.
        "PROXIES": "",
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
    try:
        with open(header_file, encoding="utf-8", errors="replace") as fh:
            found = [ln.split(":", 1)[1].strip()
                     for ln in fh if ln.lower().startswith("location:")]
        return found[-1] if found else ""
    except OSError:
        return ""


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
    return r


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
        # Так Google отвечает на адреса, которые считает подозрительными.
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


def check_node(entry, port_base):
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
        result.update(probe_gemini(f"socks5h://127.0.0.1:{port}"))
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

def proxies_source():
    """Список прокси приходит из секрета PROXIES, а при его отсутствии — из файла."""
    if CFG["PROXIES"].strip():
        return CFG["PROXIES"].splitlines()
    path = CFG["PROXIES_FILE"]
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read().splitlines()
    return []


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


def check_proxy(p):
    auth = f"{urllib.parse.quote(p['user'])}:{urllib.parse.quote(p['password'])}"
    http_proxy = f"http://{auth}@{p['host']}:{p['http_port']}"
    socks_proxy = f"socks5h://{auth}@{p['host']}:{p['socks_port']}"

    result = {"kind": "proxy", "name": p["host"],
              "addr": f"{p['host']}:{p['http_port']}/{p['socks_port']}"}
    result.update(probe_gemini(http_proxy))

    code, _, _, _, _ = curl(IPINFO, socks_proxy, timeout=15)
    result["socks_ok"] = code == 200
    if not result["socks_ok"] and result["status"] == "ok":
        result["status"] = "degraded"
        result["note"] = f"HTTP {p['http_port']} работает, SOCKS5 {p['socks_port']} — нет"
    return result


# ─────────────────────────── отчёт ───────────────────────────

def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


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
    data = urllib.parse.urlencode(
        {k: v for k, v in params.items() if v is not None}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}", data=data)
    with urllib.request.urlopen(req, timeout=25) as resp:
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

def run_all():
    """Прогоняет все проверки и возвращает (узлы, прокси)."""
    port_base = int(CFG["SOCKS_PORT_BASE"])
    workers = int(CFG["WORKERS"])
    nodes, proxies = [], []

    if CFG["CHECK_NODES"] == "1" and CFG["SUB_URL"]:
        try:
            entries = fetch_subscription(CFG["SUB_URL"])
            log(f"подписка: {len(entries)} записей")
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(check_node, e, port_base + i * 5)
                           for i, e in enumerate(entries)]
                nodes = [f.result() for f in futures]
        except Exception as exc:  # noqa: BLE001
            log(f"подписка недоступна: {exc}")
            nodes = [{"kind": "node", "name": "подписка целиком", "status": "down",
                      "note": f"не удалось получить список узлов: {exc}"}]

    if CFG["CHECK_PROXIES"] == "1":
        plist = parse_proxies(proxies_source())
        log(f"прокси: {len(plist)} штук")
        if plist:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                proxies = list(pool.map(check_proxy, plist))

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
        if digest_due or force:
            state["last_digest"] = digest_slot
    else:
        log("состояние не изменилось, дайджест не по расписанию — молчим")

    state["statuses"] = current
    state["updated_at"] = now.isoformat()
    save_state(state)


if __name__ == "__main__":
    main()
