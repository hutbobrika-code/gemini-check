"""Клиент Bot API: отправка, удаление, файлы, получение команд."""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
import uuid

from . import log

LIMIT = 3900   # у Telegram 4096, оставляем запас на разметку


class Telegram:
    def __init__(self, token: str, chats: list[str]) -> None:
        self.url = f"https://api.telegram.org/bot{token}"
        self.chats = chats

    def call(self, method: str, **params) -> dict:
        data = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        # На длинном опросе Telegram сам держит соединение timeout секунд.
        wait = int(params.get("timeout") or 0) + 20
        with urllib.request.urlopen(f"{self.url}/{method}", data.encode(), timeout=wait) as resp:
            return json.loads(resp.read())

    def updates(self, offset: int, wait: int) -> list[dict]:
        return self.call("getUpdates", offset=offset, timeout=wait,
                         allowed_updates='["message"]')["result"]

    def send(self, text: str, chat: str | None = None,
             reply_to: int | None = None) -> list[tuple[str, int]]:
        """Отправляет (длинное — частями). Возвращает (чат, id) отправленного."""
        sent = []
        for chat_id in [chat] if chat else self.chats:
            for i, part in enumerate(split(text)):
                message = self._send_part(chat_id, part, reply_to if i == 0 else None)
                if message:
                    sent.append((chat_id, message))
        return sent

    def delete(self, messages: list) -> None:
        for chat, message_id in messages:
            try:
                self.call("deleteMessage", chat_id=chat, message_id=message_id)
            except (OSError, ValueError) as exc:
                # Сообщения старше 48 часов бот удалить уже не может.
                log(f"сообщение {message_id} не удалено: {_reason(exc)}")

    def send_file(self, name: str, content: str, caption: str, chat: str) -> None:
        boundary = uuid.uuid4().hex
        fields = {"chat_id": chat, "caption": caption}
        parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'
                 for key, value in fields.items()]
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="document"; '
                     f'filename="{name}"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
                     f'{content}\r\n--{boundary}--\r\n')
        request = urllib.request.Request(
            f"{self.url}/sendDocument", "".join(parts).encode(),
            {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        try:
            urllib.request.urlopen(request, timeout=40).close()
        except OSError as exc:
            log(f"файл {name} не отправлен: {_reason(exc)}")

    def _send_part(self, chat: str, text: str, reply_to: int | None) -> int | None:
        params = {"chat_id": chat, "text": text, "parse_mode": "HTML",
                  "disable_web_page_preview": "true"}
        # Команду могли успеть удалить — тогда отвечаем обычным сообщением.
        for reply in (reply_to, None) if reply_to else (None,):
            try:
                answer = self.call("sendMessage", **params, reply_to_message_id=reply)
                return answer["result"]["message_id"]
            except (OSError, ValueError, KeyError) as exc:
                log(f"не отправлено в {chat}: {_reason(exc)}")
        return None


def split(text: str, limit: int = LIMIT) -> list[str]:
    """Режет длинный текст по абзацам, не разрывая раскрывающиеся цитаты:
    разрыв внутри <blockquote> ломает разметку, и Telegram не примет сообщение."""
    if len(text) <= limit:
        return [text]

    units = []
    for block in re.split(r"(<blockquote[^>]*>[\s\S]*?</blockquote>)", text):
        quote = re.fullmatch(r"(<blockquote[^>]*>)([\s\S]*)</blockquote>", block)
        if quote:
            units += _by_lines(quote[2], limit, quote[1], "</blockquote>")
        else:
            for paragraph in block.split("\n\n"):
                if paragraph.strip():
                    units += _by_lines(paragraph, limit)

    parts, current = [], ""
    for unit in units:
        if current and len(current) + len(unit) + 2 > limit:
            parts.append(current)
            current = ""
        current = f"{current}\n\n{unit}" if current else unit
    return parts + [current] if current else parts


def _by_lines(text: str, limit: int, opening: str = "", closing: str = "") -> list[str]:
    """Кусок длиннее лимита — делим по строкам, каждую часть оборачивая заново."""
    room = limit - len(opening) - len(closing)
    pieces, current = [], ""
    for line in text.strip().split("\n"):
        if current and len(current) + len(line) + 1 > room:
            pieces.append(current)
            current = ""
        current = f"{current}\n{line}" if current else line
    pieces.append(current)
    return [opening + piece + closing for piece in pieces]


def _reason(exc: Exception) -> str:
    """У ошибок Bot API объяснение лежит в теле ответа."""
    try:
        return json.loads(exc.read())["description"]
    except (AttributeError, ValueError, KeyError):
        return str(exc)
