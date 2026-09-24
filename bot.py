# Бот проверки доступности. Крутится сменами в GitHub Actions: слушает команды
# в телеге, раз в час проверяет все точки и пишет в группу если что-то поменялось.
#
#   python3 bot.py          смена на SHIFT_MINUTES минут
#   python3 bot.py --once   одна проверка, вывод в консоль, без телеги

import html
import re
import sys
import threading
import time

from monitor import log, nodes, now, probes, proxies, report, state
from monitor.config import settings
from monitor.telegram import Telegram


def run_check(probe=probes.check_services):
    points = nodes.check_all(probe) if settings.sub_url else []
    points += proxies.check_all(probe)
    for p in points:
        log(f"{p.status:<8} {p.name}  {report.summary(p)}")
    return points


class BackgroundCheck:
    # проверка идёт несколько минут, поэтому в отдельном потоке,
    # иначе бот всё это время не отвечает на команды

    def __init__(self):
        self.thread = None
        self.result = []

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self):
        if self.thread is not None:  # ещё идёт или результат не забрали
            return False
        self.thread = threading.Thread(target=self.work, daemon=True)
        self.thread.start()
        return True

    def take(self):
        if self.thread is None or self.running:
            return None
        self.thread = None
        return self.result

    def work(self):
        try:
            self.result = run_check()
        except Exception as e:
            log(f"проверка упала: {e!r}")
            self.result = []


class Shift:
    def __init__(self, tg):
        self.tg = tg
        self.state = state.load()
        self.offset = state.load_offset()
        self.check = BackgroundCheck()
        self.next_check = 0
        self.waiting = {}  # chat -> id команды /status
        self.acks = []  # сообщения "проверяю...", удаляем после ответа
        self.commands = {
            "/status": self.status,
            "/ping": self.status,
            "/check": self.check_site,
            "/replaced": self.replaced,
            "/help": self.help,
            "/start": self.help,
        }

    def run(self, minutes):
        log(f"смена на {minutes} мин, проверка раз в {settings.check_every // 60} мин")
        end = time.monotonic() + minutes * 60
        while time.monotonic() < end:
            if time.monotonic() >= self.next_check:
                self.check.start()
            points = self.check.take()
            if points is not None:
                self.next_check = time.monotonic() + settings.check_every
                self.on_checked(points)
            self.poll()
        state.save(self.state)
        log("смена закончилась")

    def poll(self):
        # пока идёт проверка опрашиваем часто, чтобы ответить сразу как закончится
        wait = 10 if self.check.running else 50
        try:
            updates = self.tg.updates(self.offset, wait)
        except (OSError, ValueError) as e:
            log(f"getUpdates: {e}")
            time.sleep(5)
            return
        for u in updates:
            self.offset = u["update_id"] + 1
            if "message" in u:
                self.on_message(u["message"])
        if updates:
            state.save_offset(self.offset)

    def on_message(self, msg):
        chat = str(msg["chat"]["id"])
        text = (msg.get("text") or "").strip()
        if chat not in settings.chat_ids or not text.startswith("/"):
            return
        cmd, _, arg = text.partition(" ")
        handler = self.commands.get(cmd.split("@")[0].lower())
        if handler:
            handler(chat, msg["message_id"], arg.strip())

    def on_checked(self, points):
        if self.waiting:
            self.answer_status(points)
        self.handle_replacements([p for p in points if p.kind == "proxy"])
        self.report_changes(points)
        state.save(self.state)

    def answer_status(self, points):
        text = report.status_report(points, "📊 Статус")
        proxy_points = [p for p in points if p.kind == "proxy"]
        for chat, msg_id in self.waiting.items():
            self.tg.send(text, chat, reply_to=msg_id)
            if proxy_points:
                self.tg.send_file(f"proxy-{now():%d.%m-%H%M}.txt",
                                  report.proxy_file(proxy_points),
                                  "Список прокси с результатом проверки", chat)
        self.tg.delete(self.acks)
        self.waiting = {}
        self.acks = []

    def handle_replacements(self, proxy_points):
        requested = proxies.request_replacements(proxy_points, self.state)
        done = proxies.detect_replacements(proxy_points, self.state)
        if requested or done:
            self.tg.send(report.replacement_notice(requested, done))

    def report_changes(self, points):
        before = self.state.get("statuses", {})
        seen = state.snapshot(points)
        after = state.confirm(before, seen, self.state.setdefault("pending", {}))
        self.state["statuses"] = after
        if not before:
            log("первая проверка, запомнил состояние")
            return
        text = report.changes_report(points, before, after)
        if not text:
            log("без изменений")
            return
        # в группе держим одно сообщение об изменениях, старое удаляем
        sent = self.tg.send(text)
        if sent:
            self.tg.delete(self.state.get("last_alert", []))
            self.state["last_alert"] = sent

    def status(self, chat, msg_id, arg):
        self.waiting[chat] = msg_id
        if self.check.start():
            text = "⏳ Проверяю все площадки через все точки, это займёт несколько минут…"
        else:
            text = "⏳ Проверка уже идёт, пришлю результат как только закончится."
        self.acks += self.tg.send(text, chat, reply_to=msg_id)

    def check_site(self, chat, msg_id, arg):
        url = probes.parse_target(arg)
        if not url:
            self.tg.send("Укажите адрес: <code>/check youtube.com</code>", chat, reply_to=msg_id)
            return
        threading.Thread(target=self.check_site_bg, args=(chat, msg_id, url), daemon=True).start()

    def check_site_bg(self, chat, msg_id, url):
        ack = self.tg.send(f"⏳ Проверяю {html.escape(url)} через все точки…",
                           chat, reply_to=msg_id)
        points = run_check(probes.url_probe(url))
        self.tg.send(report.status_report(points, f"🔎 {url}"), chat, reply_to=msg_id)
        self.tg.delete(ack)

    def replaced(self, chat, msg_id, arg):
        self.tg.send(report.replacements_report(self.state), chat, reply_to=msg_id)

    def help(self, chat, msg_id, arg):
        self.tg.send(report.HELP, chat, reply_to=msg_id)


def main():
    if "--once" in sys.argv:
        text = report.status_report(run_check(), "Проверка")
        print(html.unescape(re.sub(r"<[^>]+>", "", text)))
        return
    if not settings.tg_token or not settings.chat_ids:
        sys.exit("не заданы TG_TOKEN / TG_CHAT_IDS")
    Shift(Telegram(settings.tg_token, settings.chat_ids)).run(settings.shift_minutes)


if __name__ == "__main__":
    main()
