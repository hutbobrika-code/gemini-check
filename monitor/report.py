import re
from datetime import datetime
from html import escape

from . import MSK, now
from .config import settings
from .model import BLOCKED, DEGRADED, DOWN, ICON, OK, WORD
from .probes import NAMES

GROUPS = [("node", "Узлы подписки", "узлы"), ("proxy", "Прокси", "прокси")]
LEGEND = "<i>🚫 регион не поддерживается · ❌ не отвечает · ⚠️ частично · 🔄 автопродление</i>"

HELP = """<b>Бот проверки доступности</b>

/status - проверить Gemini, ChatGPT, YouTube и остальное через все узлы и прокси
/check <i>адрес</i> - проверить любой сайт, например <code>/check youtube.com</code>
/replaced - история замен прокси

Сам бот пишет только когда что-то поменялось."""


def status_report(points, title):
    lines = [header_line(title), ""]
    for label, _, group in groups(points):
        lines.append(f"{label}: <b>{count_ok(group)} из {len(group)}</b> без замечаний")

    order = {DOWN: 0, BLOCKED: 1, DEGRADED: 2}
    bad = sorted([p for p in points if p.status != OK], key=lambda p: order[p.status])
    if bad:
        lines += ["", "<b>Проблемы</b>"]
        for p in bad:
            lines.append(point_title(p))
            lines += indent(problems(p))
            lines.append("")
        lines.pop()

    good = [p for p in points if p.status == OK]
    if good:
        caption = f"Без замечаний — {plural(len(good), 'точка', 'точки', 'точек')}"
        if any(p.services for p in good):
            n = plural(len(NAMES), "площадка", "площадки", "площадок")
            caption += f", все {n} открываются"
        lines += ["", quote(caption, good_lines(good))]

    services = by_service(points)
    if services:
        caption = f"По площадкам — из {plural(len(points), 'точки', 'точек', 'точек')}"
        lines += ["", quote(caption, services)]

    lines += ["", LEGEND]
    return "\n".join(lines)


def changes_report(points, before, after):
    # пустая строка значит что писать не о чем
    points = [p.as_of(after) for p in points]
    blocks = []
    worse = False
    for p in points:
        change = point_change(p, before)
        if change:
            text, got_worse = change
            blocks.append(text)
            worse = worse or got_worse
    if not blocks:
        return ""

    totals = " · ".join(f"{short} {count_ok(g)} из {len(g)}" for _, short, g in groups(points))
    head = "🔴 Изменения" if worse else "🟢 Восстановление"
    return "\n\n".join([header_line(head), *blocks, f"<i>Без замечаний: {totals}</i>"])


def point_change(p, before):
    was = before.get(p.key)
    moved = {}  # (было, стало) -> площадки
    for sid, r in p.services.items():
        old = before.get(f"{p.key}/{sid}")
        if old == r.status or (old is None and r.status == OK):
            continue
        moved.setdefault((old, r.status), []).append(label(sid, r))

    if was is None:
        if p.status == OK:
            return None
        body = ["новая точка", *problems(p)]
        worse = True
    elif was != p.status and (DOWN in (was, p.status) or not moved):
        # поменялся сам канал: упал или поднялся
        a = arrow(was, p.status)
        body = [f"{a}  снова работает"] if p.status == OK else [a, *problems(p)]
        worse = p.status != OK
    elif moved:
        body = [f"{arrow(old, new)}  {', '.join(names)}" for (old, new), names in moved.items()]
        worse = any(new != OK for _, new in moved)
    else:
        return None
    return "\n".join([point_title(p), *indent(body)]), worse


def problems(p):
    if p.status == DOWN and p.note:
        return [esc(p.note)]
    blocked = [esc(NAMES[sid]) for sid, r in p.services.items() if r.status == BLOCKED]
    down = [esc(NAMES[sid]) for sid, r in p.services.items() if r.status == DOWN]
    partial = [(sid, r) for sid, r in p.services.items() if r.status == DEGRADED]

    lines = [esc(p.note)] if p.note else []
    if blocked:
        lines.append("🚫 регион: " + ", ".join(blocked))
    if down:
        verb = "не отвечает" if len(down) == 1 else "не отвечают"
        lines.append(f"❌ {verb}: " + ", ".join(down))
    for sid, r in partial:
        lines.append(f"⚠️ {esc(NAMES[sid])}" + (f" — {esc(r.note)}" if r.note else ""))
    return lines


def good_lines(points):
    lines = []
    for title, _, group in groups(points):
        lines.append(f"<i>{title}</i>")
        for p in group:
            parts = [f"✅ {esc(clean(p.name))}", esc(p.country), esc(p.note), rent(p)]
            lines.append(" · ".join(x for x in parts if x))
    return lines


def by_service(points):
    # то же самое, но со стороны площадки: где открывается, а где нет
    points = [p for p in points if p.services]
    everywhere = []
    lines = []
    for sid, name in NAMES.items():
        checked = [p for p in points if sid in p.services]
        if not checked:
            continue
        failed = {BLOCKED: [], DOWN: [], DEGRADED: []}
        for p in checked:
            r = p.services[sid]
            if r.status != OK:
                note = f" ({esc(r.note)})" if r.note else ""
                failed[r.status].append(esc(plain(p.name)) + note)

        n_bad = sum(len(v) for v in failed.values())
        if n_bad == 0:
            everywhere.append(esc(name))
            continue
        lines.append(f"<b>{esc(name)}</b> — {len(checked) - n_bad} из {len(checked)}")
        for status, names in failed.items():
            if names:
                lines.append(f"    {ICON[status]} " + ", ".join(names))
    if everywhere:
        lines.insert(0, "✅ Везде: " + ", ".join(everywhere))
    return lines


def replacement_notice(requested, done):
    lines = ["<b>🔁 Замена адресов</b>", ""]
    lines += [esc(x) for x in done]
    if done:
        lines += ["", "⚠️ Новый адрес нужно прописать в Remnawave, сам он туда не попадёт."]
    if requested:
        lines += ["", "<i>Заявки продавцу:</i>"]
        lines += [esc(x) for x in requested]
    return "\n".join(lines)


def replacements_report(state, limit=20):
    history = state.get("replacement_log", [])
    lines = ["<b>🔁 Замены адресов</b>", ""]
    if not history:
        lines.append("Замен не было, все адреса те, что выдал продавец.")
    for e in history[-limit:]:
        country = f" · {esc(e['country'])}" if e.get("country") else ""
        lines.append(f"{esc(e['old'])} → <b>{esc(e['new'])}</b>{country}")
        lines.append(f"    {when(e['when'])} · причина: {esc(e.get('reason', '-'))}")
    if history:
        lines += ["", f"Всего замен: {len(history)}"]

    requests = list(state.get("replaced", {}).items())[-10:]
    if requests:
        lines += ["", "<i>Последние заявки продавцу:</i>"]
        lines += [f"{esc(ip)} - {when(t)}" for ip, t in requests]
    return "\n".join(lines)


def proxy_file(points):
    lines = [f"# Прокси и результат проверки, {now():%d.%m.%Y %H:%M} МСК",
             "# протокол://логин:пароль@адрес:порт", ""]
    for p in points:
        details = "; ".join(x for x in (p.country, summary(p), rent_text(p)) if x)
        head = f"# {p.name} - {WORD[p.status]}"
        if details:
            head += f" ({details})"
        lines.append(head)
        lines.append(f"http://{p.login}:{p.password}@{p.name}:{p.http_port}")
        lines.append(f"socks5://{p.login}:{p.password}@{p.name}:{p.socks_port}")
        lines.append("")
    lines.append(f"# Рабочих: {count_ok(points)} из {len(points)}")
    return "\n".join(lines)


def summary(p):
    # для логов и файла, без html
    failed = [label(sid, r, html=False) + " " + ICON[r.status]
              for sid, r in p.services.items() if r.status != OK]
    return ", ".join(x for x in [p.note, *failed] if x)


def plural(n, one, few, many):
    if n % 10 == 1 and n % 100 != 11:
        word = one
    elif 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        word = few
    else:
        word = many
    return f"{n} {word}"


def label(sid, r, html=True):
    e = esc if html else str
    text = e(NAMES.get(sid, sid))
    if r.status == DEGRADED and r.note:
        text += f" ({e(r.note)})"
    return text


def groups(points):
    for kind, name, short in GROUPS:
        group = [p for p in points if p.kind == kind]
        if group:
            yield name, short, group


def header_line(title):
    return f"<b>{esc(title)}</b> · {now():%d.%m %H:%M} МСК"


def point_title(p):
    country = f" · {esc(p.country)}" if p.country else ""
    return f"{ICON[p.status]} <b>{esc(clean(p.name))}</b>{country}"


def quote(caption, lines):
    return f"<blockquote expandable><b>{caption}</b>\n" + "\n".join(lines) + "</blockquote>"


def indent(lines):
    return ["    " + line for line in lines]


def arrow(old, new):
    return f"{ICON.get(old, '❔')} → {ICON[new]}"


def rent(p):
    if not p.date_end:
        return ""
    end = esc(p.date_end.rsplit(".", 1)[0])  # без года
    left = days_left(p.date_end)
    if p.auto_renew:
        return f"до {end} 🔄"
    if left is not None and left < 0:
        return f"аренда кончилась {end} ⛔"
    if left is not None and left <= settings.expiry_warn_days:
        return f"до {end} ⏳"
    return f"до {end}"


def rent_text(p):
    if not p.date_end:
        return ""
    text = f"аренда до {p.date_end}"
    left = days_left(p.date_end)
    if left is not None:
        text += f", осталось {plural(max(left, 0), 'день', 'дня', 'дней')}"
    if p.auto_renew:
        text += ", автопродление"
    return text


def days_left(date_end):
    try:
        end = datetime.strptime(date_end.strip(), "%d.%m.%Y").replace(tzinfo=MSK)
    except ValueError:
        return None
    return (end - now()).days


def when(iso):
    return esc(iso[:16].replace("T", " ")) + " МСК"


def count_ok(points):
    return sum(1 for p in points if p.status == OK)


def clean(name):
    return " ".join(name.replace("☑️", "").split())


EMOJI = re.compile(r"[\U0001F1E6-\U0001F1FF\U0001F300-\U0001FAFF☀-➿⭐️‍]")


def plain(name):
    # в перечислениях флаги только мешают
    return " ".join(EMOJI.sub("", clean(name)).split()).strip(" -·")


def esc(text):
    return escape(str(text or ""), quote=False)
