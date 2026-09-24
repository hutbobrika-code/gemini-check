"""Тексты сообщений в Telegram."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime
from html import escape

from . import MSK, now
from .config import settings
from .model import BLOCKED, DEGRADED, DOWN, ICON, OK, WORD, Point, Result
from .probes import NAMES

GROUPS = (("node", "Узлы подписки", "узлы"), ("proxy", "Прокси", "прокси"))
LEGEND = "<i>🚫 регион не поддерживается · ❌ не отвечает · ⚠️ частично · 🔄 автопродление</i>"

HELP = """<b>Бот проверки доступности</b>

/status — Gemini, ChatGPT, Claude, YouTube и другие площадки через все узлы \
подписки и прокси, с файлом списка прокси
/check <i>адрес</i> — любой сайт через те же точки, например <code>/check youtube.com</code>
/replaced — какие адреса прокси меняли, когда и почему

Сам бот пишет только об изменениях и держит в группе одно такое сообщение — \
новое заменяет прошлое."""


def status_report(points: list[Point], title: str) -> str:
    lines = [_title(title), ""]
    for label, _, group in _groups(points):
        lines.append(f"{label}: <b>{_healthy(group)} из {len(group)}</b> без замечаний")

    order = {DOWN: 0, BLOCKED: 1, DEGRADED: 2}
    problems = sorted((p for p in points if p.status != OK), key=lambda p: order[p.status])
    if problems:
        lines += ["", "<b>Проблемы</b>"]
        for point in problems:
            lines += [_header(point), *_indent(_problems(point)), ""]
        lines.pop()

    healthy = [p for p in points if p.status == OK]
    if healthy:
        caption = f"Без замечаний — {plural(len(healthy), 'точка', 'точки', 'точек')}"
        if any(p.services for p in healthy):
            caption += f", все {plural(len(NAMES), 'площадка', 'площадки', 'площадок')} открываются"
        lines += ["", _quote(caption, _healthy_lines(healthy))]

    by_service = _by_service(points)
    if by_service:
        caption = f"По площадкам — из {plural(len(points), 'точки', 'точек', 'точек')}"
        lines += ["", _quote(caption, by_service)]

    return "\n".join(lines + ["", LEGEND])


def changes_report(points: list[Point], before: dict[str, str], after: dict[str, str]) -> str:
    """Что изменилось между двумя снимками статусов. Пусто — сообщать не о чем."""
    points = [p.as_of(after) for p in points]
    changes = [change for p in points if (change := _change(p, before))]
    if not changes:
        return ""
    head = "🔴 Изменения" if any(worse for _, worse in changes) else "🟢 Восстановление"
    totals = " · ".join(f"{short} {_healthy(group)} из {len(group)}"
                        for _, short, group in _groups(points))
    return "\n\n".join([_title(head), *(block for block, _ in changes),
                        f"<i>Без замечаний: {totals}</i>"])


def replacement_notice(requested: list[str], done: list[str]) -> str:
    lines = ["<b>🔁 Замена адресов</b>", "", *map(_e, done)]
    if done:
        lines += ["", "⚠️ Новый адрес нужно прописать в Remnawave — сам он туда не попадёт."]
    if requested:
        lines += ["", "<i>Заявки продавцу:</i>", *map(_e, requested)]
    return "\n".join(lines)


def replacements_report(state: dict, limit: int = 20) -> str:
    history = state.get("replacement_log", [])
    lines = ["<b>🔁 Замены адресов</b>", ""]
    if not history:
        lines.append("Замен не было — все адреса те, что выдал продавец.")
    for entry in history[-limit:]:
        country = f" · {_e(entry['country'])}" if entry.get("country") else ""
        lines.append(f"{_e(entry['old'])} → <b>{_e(entry['new'])}</b>{country}")
        lines.append(f"    {_when(entry['when'])} · причина: {_e(entry.get('reason', '—'))}")
    if history:
        lines += ["", f"Всего замен: {len(history)}"]

    requests = list(state.get("replaced", {}).items())[-10:]
    if requests:
        lines += ["", "<i>Последние заявки продавцу:</i>"]
        lines += [f"{_e(ip)} — {_when(when)}" for ip, when in requests]
    return "\n".join(lines)


def proxy_file(points: list[Point]) -> str:
    """Список прокси строками, готовыми к вставке в клиент."""
    lines = [f"# Прокси и результат проверки · {now():%d.%m.%Y %H:%M} МСК",
             "# протокол://логин:пароль@адрес:порт", ""]
    for p in points:
        details = "; ".join(filter(None, (p.country, summary(p), _rent_text(p))))
        lines += [f"# {p.name} — {WORD[p.status]}" + (f" ({details})" if details else ""),
                  f"http://{p.login}:{p.password}@{p.name}:{p.http_port}",
                  f"socks5://{p.login}:{p.password}@{p.name}:{p.socks_port}",
                  ""]
    lines.append(f"# Рабочих: {_healthy(points)} из {len(points)}")
    return "\n".join(lines)


def summary(point: Point) -> str:
    """Что не так с точкой — одной строкой без разметки, для логов и файла."""
    failed = [_label(sid, r, markup=False) + f" {ICON[r.status]}"
              for sid, r in point.services.items() if r.status != OK]
    return ", ".join(filter(None, [point.note, *failed]))


def plural(n: int, one: str, few: str, many: str) -> str:
    if n % 10 == 1 and n % 100 != 11:
        word = one
    elif 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        word = few
    else:
        word = many
    return f"{n} {word}"


def _change(point: Point, before: dict[str, str]) -> tuple[str, bool] | None:
    """Блок про одну точку и признак «стало хуже». None — точка не менялась."""
    was = before.get(point.key)
    moved: dict[tuple[str | None, str], list[str]] = {}
    for sid, result in point.services.items():
        old = before.get(f"{point.key}/{sid}")
        if old != result.status and not (old is None and result.status == OK):
            moved.setdefault((old, result.status), []).append(_label(sid, result))

    if was is None:
        if point.status == OK:
            return None
        body, worse = ["новая точка", *_problems(point)], True
    elif was != point.status and (DOWN in (was, point.status) or not moved):
        arrow = _arrow(was, point.status)
        body = [f"{arrow}  снова работает"] if point.status == OK else [arrow, *_problems(point)]
        worse = point.status != OK
    elif moved:
        body = [f"{_arrow(old, new)}  {', '.join(names)}" for (old, new), names in moved.items()]
        worse = any(new != OK for _, new in moved)
    else:
        return None
    return "\n".join([_header(point), *_indent(body)]), worse


def _problems(point: Point) -> list[str]:
    """Что не так с точкой — по строке на вид проблемы."""
    if point.status == DOWN and point.note:
        return [_e(point.note)]
    blocked = [_e(NAMES[sid]) for sid, r in point.services.items() if r.status == BLOCKED]
    silent = [_e(NAMES[sid]) for sid, r in point.services.items() if r.status == DOWN]
    partial = [(sid, r) for sid, r in point.services.items() if r.status == DEGRADED]

    lines = [_e(point.note)] if point.note else []
    if blocked:
        lines.append("🚫 регион: " + ", ".join(blocked))
    if silent:
        verb = "не отвечает" if len(silent) == 1 else "не отвечают"
        lines.append(f"❌ {verb}: " + ", ".join(silent))
    lines += [f"⚠️ {_e(NAMES[sid])}" + (f" — {_e(r.note)}" if r.note else "") for sid, r in partial]
    return lines


def _healthy_lines(points: list[Point]) -> list[str]:
    lines = []
    for label, _, group in _groups(points):
        lines.append(f"<i>{label}</i>")
        for p in group:
            parts = [f"✅ {_e(_clean(p.name))}", _e(p.country), _e(p.note), _rent(p)]
            lines.append(" · ".join(filter(None, parts)))
    return lines


def _by_service(points: list[Point]) -> list[str]:
    """Взгляд со стороны площадки: где она открывается, а где именно нет."""
    points = [p for p in points if p.services]
    everywhere, lines = [], []
    for sid, name in NAMES.items():
        checked = [p for p in points if sid in p.services]
        failed: dict[str, list[str]] = {BLOCKED: [], DOWN: [], DEGRADED: []}
        for p in checked:
            result = p.services[sid]
            if result.status != OK:
                note = f" ({_e(result.note)})" if result.note else ""
                failed[result.status].append(_e(_plain(p.name)) + note)

        broken = sum(map(len, failed.values()))
        if checked and not broken:
            everywhere.append(_e(name))
        elif checked:
            lines.append(f"<b>{_e(name)}</b> — {len(checked) - broken} из {len(checked)}")
            lines += _indent(f"{ICON[status]} " + ", ".join(names)
                             for status, names in failed.items() if names)
    if everywhere:
        lines.insert(0, "✅ Везде: " + ", ".join(everywhere))
    return lines


def _groups(points: list[Point]) -> Iterator[tuple[str, str, list[Point]]]:
    for kind, label, short in GROUPS:
        group = [p for p in points if p.kind == kind]
        if group:
            yield label, short, group


def _label(sid: str, result: Result, markup: bool = True) -> str:
    """«Gemini» или «Gemini (капча Google)», если площадка работает частично."""
    esc = _e if markup else str
    label = esc(NAMES.get(sid, sid))
    if result.status == DEGRADED and result.note:
        label += f" ({esc(result.note)})"
    return label


def _title(title: str) -> str:
    return f"<b>{_e(title)}</b> · {now():%d.%m %H:%M} МСК"


def _header(point: Point) -> str:
    country = f" · {_e(point.country)}" if point.country else ""
    return f"{ICON[point.status]} <b>{_e(_clean(point.name))}</b>{country}"


def _quote(caption: str, lines: list[str]) -> str:
    return f"<blockquote expandable><b>{caption}</b>\n" + "\n".join(lines) + "</blockquote>"


def _indent(lines) -> list[str]:
    return [f"    {line}" for line in lines]


def _arrow(old: str | None, new: str) -> str:
    return f"{ICON.get(old, '❔')} → {ICON[new]}"


def _rent(point: Point) -> str:
    if not point.date_end:
        return ""
    end = _e(point.date_end.rsplit(".", 1)[0])
    left = _days_left(point.date_end)
    if point.auto_renew:
        return f"до {end} 🔄"
    if left is not None and left < 0:
        return f"аренда кончилась {end} ⛔"
    if left is not None and left <= settings.expiry_warn_days:
        return f"до {end} ⏳"
    return f"до {end}"


def _rent_text(point: Point) -> str:
    if not point.date_end:
        return ""
    parts = [f"аренда до {point.date_end}"]
    left = _days_left(point.date_end)
    if left is not None:
        parts.append(f"осталось {plural(max(left, 0), 'день', 'дня', 'дней')}")
    if point.auto_renew:
        parts.append("автопродление")
    return ", ".join(parts)


def _days_left(date_end: str) -> int | None:
    try:
        end = datetime.strptime(date_end.strip(), "%d.%m.%Y").replace(tzinfo=MSK)
    except ValueError:
        return None
    return (end - now()).days


def _when(iso: str) -> str:
    return _e(iso[:16].replace("T", " ")) + " МСК"


def _healthy(points: list[Point]) -> int:
    return sum(p.status == OK for p in points)


def _clean(name: str) -> str:
    return " ".join(name.replace("☑️", "").split())


def _plain(name: str) -> str:
    """Имя без флагов и значков — в перечислениях эмодзи только мешают."""
    name = re.sub(r"[\U0001F1E6-\U0001F1FF\U0001F300-\U0001FAFF☀-➿⭐️‍]",
                  "", _clean(name))
    return " ".join(name.split()).strip(" -·")


def _e(text: object) -> str:
    return escape(str(text or ""), quote=False)
