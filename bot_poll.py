#!/usr/bin/env python3
"""
Обработчик команд бота. Забирает накопившиеся сообщения через getUpdates и,
если кто-то написал /status, прогоняет свежую проверку и отвечает в тот же чат.

Постоянного процесса нет — скрипт запускается по расписанию из GitHub Actions,
поэтому ответ приходит не мгновенно, а на ближайшем тике (см. commands.yml).
Смещение (offset) хранится в state/tg_offset.json и коммитится обратно в репозиторий,
иначе одна и та же команда обрабатывалась бы на каждом запуске заново.
"""

import json
import os
import sys

import check

OFFSET_FILE = os.path.join(check.BASE, "state", "tg_offset.json")
COMMANDS = ("/status", "/check", "/ping")

HELP = (
    "<b>Бот проверки Gemini</b>\n\n"
    "/status — прогнать проверку прямо сейчас и показать, где Gemini открывается\n\n"
    "Сам по себе бот молчит: сообщение приходит только когда точка меняет "
    "состояние — упала или поднялась."
)


def load_offset():
    try:
        with open(OFFSET_FILE, encoding="utf-8") as fh:
            return json.load(fh).get("offset", 0)
    except (OSError, json.JSONDecodeError):
        return 0


def save_offset(offset):
    os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
    with open(OFFSET_FILE, "w", encoding="utf-8") as fh:
        json.dump({"offset": offset}, fh)


def allowed_chats():
    return {c.strip() for c in check.CFG["TG_CHAT_IDS"].split(",") if c.strip()}


def main():
    offset = load_offset()
    try:
        resp = check.tg_api("getUpdates", offset=offset, timeout=0, limit=100,
                            allowed_updates=json.dumps(["message"]))
    except Exception as exc:  # noqa: BLE001
        check.log(f"getUpdates не отработал: {exc}")
        return 1

    updates = resp.get("result", [])
    check.log(f"получено обновлений: {len(updates)}")
    if not updates:
        return 0

    allowed = allowed_chats()
    # Одна команда на чат: если /status написали несколько раз подряд,
    # незачем гонять проверку и слать одинаковый отчёт по разу на каждую.
    requests = {}  # chat_id -> message_id последней команды

    for upd in updates:
        offset = max(offset, upd["update_id"] + 1)
        msg = upd.get("message") or {}
        text = (msg.get("text") or "").strip()
        chat_id = str((msg.get("chat") or {}).get("id", ""))
        if not text.startswith("/") or chat_id not in allowed:
            continue
        cmd = text.split()[0].split("@")[0].lower()
        if cmd in COMMANDS:
            requests[chat_id] = msg.get("message_id")
        elif cmd in ("/help", "/start"):
            check.send_telegram(HELP, chat_ids=[chat_id],
                                reply_to=msg.get("message_id"))

    # Смещение сохраняем сразу: иначе упавшая проверка заставит бота
    # отвечать на ту же команду при каждом следующем запуске.
    save_offset(offset)

    if not requests:
        return 0

    for chat_id, msg_id in requests.items():
        check.send_telegram("⏳ Проверяю, это займёт около минуты…",
                            chat_ids=[chat_id], reply_to=msg_id)

    nodes, proxies = check.run_all()
    text = check.render(nodes, proxies, digest=True, title="📊 Статус по запросу")
    for chat_id, msg_id in requests.items():
        check.send_telegram(text, chat_ids=[chat_id], reply_to=msg_id)

    # Раз проверка всё равно прогнана — обновим состояние, чтобы плановый
    # запуск не прислал следом «изменение», о котором уже отчитались.
    state = check.load_state()
    state["statuses"] = {f"{r['kind']}:{r['name']}": r.get("status")
                         for r in nodes + proxies}
    check.save_state(state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
