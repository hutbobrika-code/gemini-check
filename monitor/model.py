from dataclasses import dataclass, field, replace

OK, BLOCKED, DOWN, DEGRADED = "ok", "blocked", "down", "degraded"

ICON = {OK: "✅", BLOCKED: "🚫", DOWN: "❌", DEGRADED: "⚠️"}
WORD = {OK: "работает", BLOCKED: "заблокирован", DOWN: "не работает",
        DEGRADED: "работает частично"}

CAPTCHA = "капча Google"


@dataclass
class Result:
    status: str
    note: str = ""


@dataclass
class Point:
    kind: str  # node или proxy
    name: str
    status: str = DOWN
    note: str = ""  # проблема с самим каналом: хост не отвечает, туннель не поднялся
    country: str = ""
    exit_ip: str = ""
    latency: float = 0.0
    services: dict = field(default_factory=dict)

    # только у прокси
    ps_id: int | None = None
    login: str = ""
    password: str = ""
    http_port: int = 0
    socks_port: int = 0
    date_end: str = ""
    auto_renew: bool = False

    @property
    def key(self):
        return f"{self.kind}:{self.name}"

    @property
    def captcha(self):
        return any(r.note == CAPTCHA for r in self.services.values())

    def as_of(self, statuses):
        services = {sid: replace(r, status=statuses.get(f"{self.key}/{sid}", r.status))
                    for sid, r in self.services.items()}
        return replace(self, status=statuses.get(self.key, self.status), services=services)


def overall(services):
    statuses = {r.status for r in services.values()}
    if statuses <= {OK}:
        return OK
    if statuses == {DOWN}:
        return DOWN
    return BLOCKED if BLOCKED in statuses else DEGRADED
