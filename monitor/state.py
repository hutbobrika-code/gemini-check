import json

from . import now
from .config import settings

FIELDS = ("statuses", "pending", "last_alert", "replaced", "replace_reason", "ips",
          "replacement_log")


def load():
    return read_json(settings.state_dir / "state.json")


def save(state):
    data = {k: state[k] for k in FIELDS if k in state}
    data["updated_at"] = now().isoformat()
    write_json(settings.state_dir / "state.json", data)


def load_offset():
    return read_json(settings.state_dir / "tg_offset.json").get("offset", 0)


def save_offset(offset):
    write_json(settings.state_dir / "tg_offset.json", {"offset": offset})


def snapshot(points):
    # "node:Польша" -> статус точки, "node:Польша/youtube" -> статус площадки на ней
    statuses = {}
    for p in points:
        statuses[p.key] = p.status
        for sid, r in p.services.items():
            statuses[f"{p.key}/{sid}"] = r.status
    return statuses


def confirm(before, seen, pending):
    # изменение принимаем только если оно повторилось две проверки подряд,
    # иначе каждый случайный таймаут прилетал бы в чат.
    # в pending лежит то, что увидели один раз
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


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)
