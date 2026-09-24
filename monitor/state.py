"""Состояние между проверками. Лежит в state/ и коммитится в конце смены."""

from __future__ import annotations

import json
from pathlib import Path

from . import now
from .config import settings
from .model import Point

FIELDS = ("statuses", "pending", "last_alert", "replaced", "replace_reason", "ips",
          "replacement_log")


def load() -> dict:
    return _read(settings.state_dir / "state.json")


def save(state: dict) -> None:
    data = {key: state[key] for key in FIELDS if key in state}
    _write(settings.state_dir / "state.json", data | {"updated_at": now().isoformat()})


def load_offset() -> int:
    return _read(settings.state_dir / "tg_offset.json").get("offset", 0)


def save_offset(offset: int) -> None:
    _write(settings.state_dir / "tg_offset.json", {"offset": offset})


def snapshot(points: list[Point]) -> dict[str, str]:
    """Статус каждой точки и каждой площадки на ней: «node:Польша/youtube» → «down»."""
    statuses = {}
    for point in points:
        statuses[point.key] = point.status
        for sid, result in point.services.items():
            statuses[f"{point.key}/{sid}"] = result.status
    return statuses


def confirm(before: dict[str, str], seen: dict[str, str],
            pending: dict[str, str]) -> dict[str, str]:
    """Изменение принимается, только если продержалось две проверки подряд.

    Иначе одиночные таймауты каждый час сыпали бы «✅→❌» и «❌→✅» по одним
    и тем же местам. pending — то, что замечено один раз и ждёт подтверждения.
    """
    after = dict(before)
    for key, status in seen.items():
        if key not in before or pending.get(key) == status:
            after[key] = status
            pending.pop(key, None)
        elif status == before[key]:
            pending.pop(key, None)
        else:
            pending[key] = status
    for key in pending.keys() - seen.keys():
        del pending[key]
    return after


def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)
