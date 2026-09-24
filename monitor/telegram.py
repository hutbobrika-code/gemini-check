import json
import re
import urllib.parse
import urllib.request
import uuid

from . import log

LIMIT = 3900  # у телеги 4096, запас под теги


class Telegram:
    def __init__(self, token, chats):
        self.url = f"https://api.telegram.org/bot{token}"
        self.chats = chats

    def call(self, method, **params):
        data = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        timeout = int(params.get("timeout") or 0) + 20  # long polling держит соединение
        with urllib.request.urlopen(f"{self.url}/{method}", data.encode(), timeout=timeout) as r:
            return json.loads(r.read())

    def updates(self, offset, wait):
        res = self.call("getUpdates", offset=offset, timeout=wait, allowed_updates='["message"]')
        return res["result"]

    def send(self, text, chat=None, reply_to=None):
        # возвращает [(chat, message_id)], чтобы потом можно было удалить
        sent = []
        for chat_id in [chat] if chat else self.chats:
            for i, part in enumerate(split(text)):
                msg_id = self.send_part(chat_id, part, reply_to if i == 0 else None)
                if msg_id:
                    sent.append((chat_id, msg_id))
        return sent

    def send_part(self, chat, text, reply_to):
        params = {"chat_id": chat, "text": text, "parse_mode": "HTML",
                  "disable_web_page_preview": "true"}
        # если команду уже удалили, reply не пройдёт - тогда шлём без него
        for reply in (reply_to, None) if reply_to else (None,):
            try:
                res = self.call("sendMessage", **params, reply_to_message_id=reply)
                return res["result"]["message_id"]
            except (OSError, ValueError, KeyError) as e:
                log(f"не отправилось в {chat}: {error_text(e)}")
        return None

    def delete(self, messages):
        for chat, msg_id in messages:
            try:
                self.call("deleteMessage", chat_id=chat, message_id=msg_id)
            except (OSError, ValueError) as e:
                # старше 48 часов бот удалить не может
                log(f"не удалилось сообщение {msg_id}: {error_text(e)}")

    def send_file(self, name, content, caption, chat):
        boundary = uuid.uuid4().hex
        body = ""
        for key, value in (("chat_id", chat), ("caption", caption)):
            body += f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n'
            body += f"{value}\r\n"
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="document"; '
                 f'filename="{name}"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
                 f'{content}\r\n--{boundary}--\r\n')
        req = urllib.request.Request(f"{self.url}/sendDocument", body.encode(),
                                     {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        try:
            urllib.request.urlopen(req, timeout=40).close()
        except OSError as e:
            log(f"файл {name} не отправился: {error_text(e)}")


def split(text, limit=LIMIT):
    # режем по абзацам. blockquote резать посередине нельзя - телега не примет
    # сообщение с битой разметкой, поэтому длинную цитату делим на несколько цитат
    if len(text) <= limit:
        return [text]

    blocks = []
    for chunk in re.split(r"(<blockquote[^>]*>[\s\S]*?</blockquote>)", text):
        m = re.fullmatch(r"(<blockquote[^>]*>)([\s\S]*)</blockquote>", chunk)
        if m:
            blocks += split_lines(m.group(2), limit, m.group(1), "</blockquote>")
            continue
        for para in chunk.split("\n\n"):
            if para.strip():
                blocks += split_lines(para, limit)

    parts = []
    cur = ""
    for b in blocks:
        if cur and len(cur) + len(b) + 2 > limit:
            parts.append(cur)
            cur = ""
        cur = cur + "\n\n" + b if cur else b
    if cur:
        parts.append(cur)
    return parts


def split_lines(text, limit, start="", end=""):
    room = limit - len(start) - len(end)
    pieces = []
    cur = ""
    for line in text.strip().split("\n"):
        if cur and len(cur) + len(line) + 1 > room:
            pieces.append(cur)
            cur = ""
        cur = cur + "\n" + line if cur else line
    pieces.append(cur)
    return [start + p + end for p in pieces]


def error_text(e):
    # у ошибок bot api описание приходит в теле ответа
    try:
        return json.loads(e.read())["description"]
    except (AttributeError, ValueError, KeyError):
        return str(e)
