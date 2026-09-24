#!/usr/bin/env python3
"""Бот мониторинга доступности.

Работает сменами в GitHub Actions: слушает команды в Telegram, раз в час
проверяет все точки и сообщает в группу об изменениях.

    python3 bot.py          смена длиной SHIFT_MINUTES
    python3 bot.py --once   одна проверка с отчётом в консоль, без Telegram
"""

from __future__ import annotations

import html
import re
import sys
import threading
import time

from monitor import log, nodes, now, probes, proxies, report, state
from monitor.config import settings
from monitor.model import Point
from monitor.telegram import Telegram


def run_check(probe: probes.Probe = probes.check_services) -> list[Point]:
    points = nodes.check_all(probe) if settings.sub_url else []
    points += proxies.check_all(probe)
    for point in points:
        log(f"{point.status:<8} {point.name}  {report.summary(point)}")
    return points


class BackgroundCheck:
    """Проверка идёт в своём потоке, чтобы бот отвечал на команды, пока она длится."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._result: list[Point] = []

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        if self._thread is not None:      # идёт или ждёт, пока заберут результат
            return False
        self._thread = threading.Thread(target=self._work, daemon=True)
        self._thread.start()
        return True

    def take(self) -> list[Point] | None:
        """Результат закончившейся проверки; None, если её нет или она ещё идёт."""
        if self._thread is None or self.running:
            return None
        self._thread = None
        return self._result

    def _work(self) -> None:
        try:
            self._result = run_check()
        except Exception as exc:          # упавшая проверка не должна ронять смену
            log(f"проверка упала: {exc!r}")
            self._result = []


class Shift:
    def __init__(self, tg: Telegram) -> None:
        self.tg = tg
        self.state = state.load()
        self.offset = state.load_offset()
        self.check = BackgroundCheck()
        self.next_check = 0.0
        self.waiting: dict[str, int] = {}      # чат → его команда /status
        self.acks: list[tuple[str, int]] = []  # «⏳ проверяю» — уберём, когда ответим
        self.commands = {
            "/status": self.status,
            "/ping": self.status,
            "/check": self.check_site,
            "/replaced": self.replaced,
            "/help": self.help,
            "/start": self.help,
        }

    def run(self, minutes: int) -> None:
        log(f"смена на {minutes} мин, проверка раз в {settings.check_every // 60} мин")
        deadline = time.monotonic() + minutes * 60
        while time.monotonic() < deadline:
            if time.monotonic() >= self.next_check:
                self.check.start()
            points = self.check.take()
            if points is not None:
                self.next_check = time.monotonic() + settings.check_every
                self.on_checked(points)
            self.poll()
        state.save(self.state)
        log("смена окончена")

    def poll(self) -> None:
        # Пока идёт проверка, опрашиваем коротко, чтобы сразу отдать результат.
        wait = 10 if self.check.running else 50
        try:
            updates = self.tg.updates(self.offset, wait)
        except (OSError, ValueError) as exc:
            log(f"опрос Telegram прервался: {exc}")
            time.sleep(5)
            return
        for update in updates:
            self.offset = update["update_id"] + 1
            if "message" in update:
                self.on_message(update["message"])
        if updates:
            state.save_offset(self.offset)

    def on_message(self, message: dict) -> None:
        chat = str(message["chat"]["id"])
        text = (message.get("text") or "").strip()
        if chat not in settings.chat_ids or not text.startswith("/"):
            return
        command, _, argument = text.partition(" ")
        handler = self.commands.get(command.split("@")[0].lower())
        if handler:
            handler(chat, message["message_id"], argument.strip())

    def on_checked(self, points: list[Point]) -> None:
        if self.waiting:
            self.answer_status(points)
        self.handle_replacements([p for p in points if p.kind == "proxy"])
        self.report_changes(points)
        state.save(self.state)

    def answer_status(self, points: list[Point]) -> None:
        text = report.status_report(points, "📊 Статус")
        proxy_points = [p for p in points if p.kind == "proxy"]
        for chat, command in self.waiting.items():
            self.tg.send(text, chat, reply_to=command)
            if proxy_points:
                self.tg.send_file(f"proxy-{now():%d.%m-%H%M}.txt", report.proxy_file(proxy_points),
                                  "Список прокси с результатом проверки", chat)
        self.tg.delete(self.acks)
        self.waiting, self.acks = {}, []

    def handle_replacements(self, proxy_points: list[Point]) -> None:
        requested = proxies.request_replacements(proxy_points, self.state)
        done = proxies.detect_replacements(proxy_points, self.state)
        if requested or done:
            self.tg.send(report.replacement_notice(requested, done))

    def report_changes(self, points: list[Point]) -> None:
        before = self.state.get("statuses", {})
        after = state.confirm(before, state.snapshot(points), self.state.setdefault("pending", {}))
        self.state["statuses"] = after
        if not before:
            log("первая проверка — состояние запомнено")
            return
        text = report.changes_report(points, before, after)
        if not text:
            log("изменений нет")
            return
        # В группе живёт одно сообщение об изменениях: новое заменяет прошлое.
        sent = self.tg.send(text)
        if sent:
            self.tg.delete(self.state.get("last_alert", []))
            self.state["last_alert"] = sent

    def status(self, chat: str, command: int, _: str) -> None:
        self.waiting[chat] = command
        if self.check.start():
            text = "⏳ Проверяю все площадки через все точки, это займёт несколько минут…"
        else:
            text = "⏳ Проверка уже идёт — пришлю результат, как только закончится."
        self.acks += self.tg.send(text, chat, reply_to=command)

    def check_site(self, chat: str, command: int, argument: str) -> None:
        url = probes.parse_target(argument)
        if not url:
            self.tg.send("Укажите адрес: <code>/check youtube.com</code>", chat, reply_to=command)
            return
        threading.Thread(target=self._check_site, args=(chat, command, url), daemon=True).start()

    def _check_site(self, chat: str, command: int, url: str) -> None:
        text = f"⏳ Проверяю {html.escape(url)} через все точки…"
        ack = self.tg.send(text, chat, reply_to=command)
        points = run_check(probes.url_probe(url))
        self.tg.send(report.status_report(points, f"🔎 {url}"), chat, reply_to=command)
        self.tg.delete(ack)

    def replaced(self, chat: str, command: int, _: str) -> None:
        self.tg.send(report.replacements_report(self.state), chat, reply_to=command)

    def help(self, chat: str, command: int, _: str) -> None:
        self.tg.send(report.HELP, chat, reply_to=command)


def main() -> None:
    if "--once" in sys.argv:
        text = report.status_report(run_check(), "Проверка")
        print(html.unescape(re.sub(r"<[^>]+>", "", text)))
        return
    if not (settings.tg_token and settings.chat_ids):
        sys.exit("нужны TG_TOKEN и TG_CHAT_IDS")
    Shift(Telegram(settings.tg_token, settings.chat_ids)).run(settings.shift_minutes)


if __name__ == "__main__":
    main()
