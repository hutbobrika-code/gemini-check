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
import threading
import time
from datetime import datetime

import check
import bot_poll

LISTEN_MINUTES = int(os.environ.get("LISTEN_MINUTES", "300"))
CHECK_EVERY = int(os.environ.get("CHECK_EVERY_SECONDS", "3600"))
POLL_TIMEOUT = 50  # столько Telegram держит соединение, если сообщений нет


class Checker:
    """Проверка в фоне: слушатель тем временем отвечает на команды.

    Пока идёт полный прогон (несколько минут), /status не должен висеть
    без ответа — он получает «принял» сразу, а результат — когда прогон кончится.
    """

    def __init__(self):
        self.thread = None
        self.result = None
        self.requests = {}   # chat_id → message_id тех, кто ждёт /status
        self.acks = []       # наши «⏳ проверяю» — убираем, когда пришёл ответ

    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self):
        if self.running():
            return False
        self.result = None

        def work():
            try:
                self.result = check.run_all()
            except Exception as exc:  # noqa: BLE001
                check.log(f"проверка упала: {exc}")
                self.result = ([], [])

        self.thread = threading.Thread(target=work, daemon=True)
        self.thread.start()
        return True

    def take(self):
        """Результат, если прогон закончился; иначе None."""
        if self.thread is None or self.running() or self.result is None:
            return None
        nodes, proxies = self.result
        self.result, self.thread = None, None
        return nodes, proxies


def handle_commands(updates, state, checker):
    allowed = bot_poll.allowed_chats()
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
            checker.requests[chat_id] = msg_id
            if checker.start():
                note = "⏳ Проверяю все площадки через все точки, это займёт несколько минут…"
            else:
                note = "⏳ Проверка уже идёт — пришлю результат, как только закончится."
            checker.acks += check.send_telegram(note, chat_ids=[chat_id], reply_to=msg_id)
        elif cmd == "/check":
            # Отдельный прогон с другой пробой — в своём потоке, чтобы не
            # держать опрос команд.
            threading.Thread(target=check_url, args=(chat_id, msg_id, arg),
                             daemon=True).start()
        elif cmd == "/replaced":
            check.send_telegram(check.render_replacements(state),
                                chat_ids=[chat_id], reply_to=msg_id)
        elif cmd in ("/help", "/start"):
            check.send_telegram(bot_poll.HELP, chat_ids=[chat_id], reply_to=msg_id)


def answer_status(nodes, proxies, requests):
    """Ответ тем, кто просил /status, по результату уже прошедшего прогона.
    Возвращает отправленные сообщения — они же становятся актуальной сводкой."""
    text = check.render(nodes, proxies, digest=True, title="📊 Статус по запросу")
    sent = []
    for chat_id, msg_id in requests.items():
        sent += check.send_telegram(text, chat_ids=[chat_id], reply_to=msg_id)
        if proxies:
            check.send_document(
                f"proxy-{datetime.now(check.MSK):%d.%m-%H%M}.txt",
                check.proxy_file_body(proxies),
                caption="Список прокси с результатом проверки",
                chat_ids=[chat_id])
    return sent


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
    nodes, proxies = check.run_all(probe=lambda px: check.probe_url(px, url),
                                   port_base=int(check.CFG["SOCKS_PORT_BASE"]) + 1000)
    text = check.render(nodes, proxies, digest=True,
                        title=f"🔎 Доступность {host}")
    check.send_telegram(text, chat_ids=[chat_id], reply_to=msg_id)


def confirm_changes(statuses, observed, state):
    """Изменение считается настоящим, если держится две проверки подряд.

    Одиночный таймаут площадки на одном узле — обычное дело; без этого
    каждый час приходила бы простыня «✅→❌» и «❌→✅» по одним и тем же местам.
    Возвращает подтверждённое состояние (с него и считаются изменения).
    """
    pending = state.setdefault("pending", {})
    confirmed = dict(statuses)
    for key, val in observed.items():
        if key not in statuses:
            confirmed[key] = val            # новая точка или площадка
            pending.pop(key, None)
        elif val == statuses[key]:
            pending.pop(key, None)          # вернулось само — ложная тревога
        elif pending.get(key) == val:
            confirmed[key] = val            # второй раз подряд — подтверждено
            pending.pop(key, None)
        else:
            pending[key] = val              # ждём следующей проверки
    for key in list(pending):
        if key not in observed:
            pending.pop(key)
    return confirmed


def with_status(r, confirmed):
    """Копия точки, где статусы заменены на подтверждённые."""
    key = f"{r['kind']}:{r['name']}"
    r = dict(r)
    r["status"] = confirmed.get(key, r.get("status"))
    if r.get("services"):
        svcs = {}
        for sid, svc in r["services"].items():
            svc = dict(svc)
            svc["status"] = confirmed.get(f"{key}/{sid}", svc.get("status"))
            svcs[sid] = svc
        r["services"] = svcs
        if r["status"] == "ok":
            r["note"] = ""
        elif r["status"] != "down":
            r["status"], r["note"] = check.summarize_services(svcs)
    return r


def scheduled_check(statuses, state, nodes, proxies, already_sent=None):
    """Разбор результата прогона: замены, оповещения об изменениях, сводка.

    already_sent — сводка, уже ушедшая в ответ на /status: второй раз её не шлём,
    а считаем актуальной вместо ежечасной.
    """
    observed = check.statuses_of(nodes + proxies)
    current = confirm_changes(statuses, observed, state)
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
        if done:
            # Панель о замене не узнаёт: там свой конфиг со старым адресом.
            lines.append("")
            lines.append("⚠️ Новый адрес нужно прописать в Remnawave — "
                         "сам он туда не попадёт.")
        if requested:
            lines.append("")
            lines.append("<i>Отправлены заявки продавцу:</i>")
            lines += [check.esc(n) for n in requested]
        check.send_telegram("\n".join(lines))
        # Историю замен сохраняем сразу: смена может оборваться, а это тот
        # факт, который потом не восстановить.
        check.save_state(state)
    replaced = requested

    if changed and statuses:
        # Точки, чьё изменение ещё не подтверждено, показываем в прежнем
        # состоянии — иначе в отчёт попадёт и то, о чём решили пока молчать.
        view = [with_status(r, current) for r in nodes + proxies]
        text = check.render_alert(view, statuses)
        if text:
            check.send_telegram(text)
    elif changed:
        check.log("первый прогон в этой смене — состояние запомнено")

    # Ежечасная сводка живёт в группе в одном экземпляре: новую шлём,
    # прошлую убираем — чтобы в чате была только актуальная картина,
    # а не стопка одинаковых отчётов.
    if already_sent:
        sent = already_sent
    else:
        text = check.render(nodes, proxies, digest=True, title="🕐 Проверка")
        if replaced:
            text += "\n\n<b>Замена адресов</b>\n" + "\n".join(check.esc(n) for n in replaced)
        sent = check.send_telegram(text)
    if sent:
        check.delete_messages([tuple(x) for x in state.get("last_report") or []])
        state["last_report"] = sent
        check.save_state(state)
    return current


def main():
    state = check.load_state()
    statuses = state.get("statuses", {})
    offset = bot_poll.load_offset()
    checker = Checker()

    deadline = time.time() + LISTEN_MINUTES * 60
    next_check = 0.0
    check.log(f"слушаю Telegram {LISTEN_MINUTES} минут, проверка раз в {CHECK_EVERY} с")

    while time.time() < deadline:
        if time.time() >= next_check and checker.start():
            next_check = time.time() + CHECK_EVERY

        done = checker.take()
        if done:
            nodes, proxies = done
            answered = []
            if checker.requests:
                answered = answer_status(nodes, proxies, checker.requests)
                check.delete_messages(checker.acks)
                checker.requests, checker.acks = {}, []
            statuses = scheduled_check(statuses, state, nodes, proxies, answered)

        # Пока идёт прогон, опрашиваем коротко, чтобы отдать результат сразу.
        poll = 10 if checker.running() else POLL_TIMEOUT
        try:
            resp = check.tg_api("getUpdates", offset=offset, timeout=poll,
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
            handle_commands(updates, state, checker)

    # Незавершённый прогон при выходе не ждём: смена и так на исходе,
    # следующая начнёт со свежей проверки.
    state["statuses"] = statuses
    state["updated_at"] = datetime.now(check.MSK).isoformat()
    check.save_state(state)
    check.log("смена окончена, состояние сохранено")
    return 0


if __name__ == "__main__":
    sys.exit(main())
