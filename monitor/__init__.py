"""Монитор доступности площадок через узлы подписки и прокси."""

from datetime import datetime, timedelta, timezone

MSK = timezone(timedelta(hours=3))


def now() -> datetime:
    return datetime.now(MSK)


def log(message: str) -> None:
    print(f"[{now():%d.%m %H:%M:%S}] {message}", flush=True)
