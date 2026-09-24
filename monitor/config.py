"""Настройки из переменных окружения — в Actions это секреты репозитория."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, "").strip() or default


class Settings:
    def __init__(self) -> None:
        self.tg_token = _env("TG_TOKEN")
        self.chat_ids = [c.strip() for c in _env("TG_CHAT_IDS").split(",") if c.strip()]

        self.sub_url = _env("SUB_URL")
        # Под этим устройством монитор числится в панели и занимает одно место в лимите.
        self.sub_hwid = _env("SUB_HWID", "gemini-check-monitor-0001")

        self.ps_api_key = _env("PS_API_KEY")
        self.proxies = _env("PROXIES")
        self.auto_replace = _env("AUTO_REPLACE", "1") == "1"
        self.replace_cooldown_hours = int(_env("REPLACE_COOLDOWN_HOURS", "6"))
        self.expiry_warn_days = int(_env("EXPIRY_WARN_DAYS", "3"))

        self.gemini_api_key = _env("GEMINI_API_KEY")
        self.gemini_model = _env("GEMINI_MODEL", "gemini-2.0-flash")

        self.xray_bin = Path(_env("XRAY_BIN", str(ROOT / "bin" / "xray")))
        self.state_dir = Path(_env("STATE_DIR", str(ROOT / "state")))
        self.workers = int(_env("WORKERS", "5"))
        self.shift_minutes = int(_env("SHIFT_MINUTES", "300"))
        self.check_every = int(_env("CHECK_EVERY_SECONDS", "3600"))


settings = Settings()
