#!/usr/bin/env python3
"""
Долгоживущий слушатель: держит длинный опрос Telegram и отвечает на команды
сразу, а не на ближайшем тике расписания. Заодно сам гоняет проверки.

Задача в GitHub Actions живёт не дольше шести часов, поэтому скрипт работает
заданный срок (LISTEN_MINUTES), сохраняет состояние и выходит — воркфлоу после
этого запускает себе смену.

Состояние держится в памяти и пишется на диск только при выходе: коммит на
каждое изменение засорял бы историю репозитория десятками записей в час.
"""

import os
import sys
import time
from datetime import datetime

import check
import bot_poll

LISTEN_MINUTES = int(os.environ.get("LISTEN_MINUTES", "300"))
CHECK_EVERY = int(os.environ.get("CHECK_EVERY_SECONDS", "3600"))
POLL_TIMEOUT = 50  # столько Telegram держит соединение, если сообщений нет


def handle_commands(updates, statuses, state):
    """Обрабатывает команды чата. Возвращает статусы, обновлённые проверкой."""
    allowed = bot_poll.allowed_chats()
    requests = {}
    for upd in updates:
        msg = upd.get("message") or {}
        text = (msg.get("text") or "").strip()
        chat_id = str((msg.get("chat") or {}).get("id", ""))
        if not text.startswith("/") or chat_id not in allowed:
            continue
        parts = text.split(maxsplit=1)
        cmd = parts[0].split("@")[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        msg_id = msg.get("message_id")

        if cmd in bot_poll.COMMANDS:
            requests[chat_id] = msg_id
        elif cmd == "/check":
            check_url(chat_id, msg_id, arg)
        elif cmd == "/replaced":
            check.send_telegram(check.render_replacements(state),
                                chat_ids=[chat_id], reply_to=msg_id)
        elif cmd in ("/help", "/start"):
            check.send_telegram(bot_poll.HELP, chat_ids=[chat_id], reply_to=msg_id)

    if not requests:
        return statuses

    for chat_id, msg_id in requests.items():
        check.send_telegram("⏳ Проверяю, это займёт около минуты…",
                            chat_ids=[chat_id], reply_to=msg_id)

    nodes, proxies = check.run_all()
    text = check.render(nodes, proxies, digest=True, title="📊 Статус по запросу")
    for chat_id, msg_id in requests.items():
        check.send_telegram(text, chat_ids=[chat_id], reply_to=msg_id)
        if proxies:
            check.send_document(
                f"proxy-{datetime.now(check.MSK):%d.%m-%H%M}.txt",
                check.proxy_file_body(proxies),
                caption="Список прокси с результатом проверки",
                chat_ids=[chat_id])

    # Проверка только что прошла — считаем её и плановой, иначе следом
    # прилетит «изменение», о котором уже отчитались.
    return {f"{r['kind']}:{r['name']}": r.get("status") for r in nodes + proxies}


def check_url(chat_id, msg_id, arg):
    """Проверяет произвольный адрес через все точки — прокси и узлы подписки."""
    url = check.normalize_target(arg)
    if not url:
        check.send_telegram(
            "Укажите адрес: <code>/check youtube.com</code> "
            "или <code>/check https://chat.openai.com</code>",
            chat_ids=[chat_id], reply_to=msg_id)
        return

    host = check.esc(url)
    check.send_telegram(f"⏳ Проверяю доступность {host} через все точки…",
                        chat_ids=[chat_id], reply_to=msg_id)
    nodes, proxies = check.run_all(probe=lambda px: check.probe_url(px, url))
    text = check.render(nodes, proxies, digest=True,
                        title=f"🔎 Доступность {host}")
    check.send_telegram(text, chat_ids=[chat_id], reply_to=msg_id)


REPORT_ALWAYS = os.environ.get("REPORT_ALWAYS", "1") == "1"


def scheduled_check(statuses, state):
    nodes, proxies = check.run_all()
    current = {f"{r['kind']}:{r['name']}": r.get("status") for r in nodes + proxies}
    changed = [k for k, v in current.items() if statuses.get(k) != v]

    # Битые адреса и адреса под капчей меняем сразу: аренда недельная,
    # ждать ручного вмешательства смысла нет.
    requested = check.auto_replace(proxies, state)
    done = check.detect_new_ips(proxies, state)

    # О заменах пишем всегда, даже в режиме «только поломки»: смена адреса —
    # это то, что нужно знать, иначе она проходит незамеченной.
    if requested or done:
        lines = ["<b>🔁 Замена адресов</b>", ""]
        lines += [check.esc(n) for n in done]
        if requested:
            lines.append("")
            lines.append("<i>Отправлены заявки продавцу:</i>")
            lines += [check.esc(n) for n in requested]
        check.send_telegram("\n".join(lines))
        # Историю замен сохраняем сразу: смена может оборваться, а это тот
        # факт, который потом не восстановить.
        check.save_state(state)
    replaced = requested

    if REPORT_ALWAYS:
        # Отчёт после каждой проверки: видно, какие адреса проверены и какие живы.
        text = check.render(nodes, proxies, digest=True, title="🕐 Плановая проверка")
        if replaced:
            text += "\n\n<b>Замена адресов</b>\n" + "\n".join(
                check.esc(n) for n in replaced)
        check.send_telegram(text)
        if proxies:
            check.send_document(
                f"proxy-{datetime.now(check.MSK):%d.%m-%H%M}.txt",
                check.proxy_file_body(proxies),
                caption="Список прокси с результатом проверки")
    elif changed and statuses:
        check.send_telegram(check.render_alert(nodes + proxies, statuses))
    elif changed:
        check.log("первый прогон в этой смене — состояние запомнено, молчим")
    else:
        check.log("состояние не изменилось — молчим")
    return current


def main():
    state = check.load_state()
    statuses = state.get("statuses", {})
    offset = bot_poll.load_offset()

    deadline = time.time() + LISTEN_MINUTES * 60
    next_check = 0.0
    check.log(f"слушаю Telegram {LISTEN_MINUTES} минут, проверка раз в {CHECK_EVERY} с")

    while time.time() < deadline:
        if time.time() >= next_check:
            statuses = scheduled_check(statuses, state)
            next_check = time.time() + CHECK_EVERY

        try:
            resp = check.tg_api("getUpdates", offset=offset, timeout=POLL_TIMEOUT,
                                limit=50, allowed_updates='["message"]')
        except Exception as exc:  # noqa: BLE001
            # Обрыв длинного опроса — обычное дело, ждём и пробуем снова.
            check.log(f"опрос прервался: {check.tg_error(exc)}")
            time.sleep(5)
            continue

        updates = resp.get("result", [])
        if updates:
            offset = max(u["update_id"] + 1 for u in updates)
            bot_poll.save_offset(offset)
            statuses = handle_commands(updates, statuses, state)

    state["statuses"] = statuses
    state["updated_at"] = datetime.now(check.MSK).isoformat()
    check.save_state(state)
    check.log("смена окончена, состояние сохранено")
    return 0


if __name__ == "__main__":
    sys.exit(main())
