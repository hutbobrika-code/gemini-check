import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def env(name, default=""):
    return os.environ.get(name, "").strip() or default


class Settings:
    def __init__(self):
        self.tg_token = env("TG_TOKEN")
        self.chat_ids = [c.strip() for c in env("TG_CHAT_IDS").split(",") if c.strip()]

        self.sub_url = env("SUB_URL")
        # hwid постоянный, чтобы в панели монитор занимал одно устройство
        self.sub_hwid = env("SUB_HWID", "gemini-check-monitor-0001")

        self.ps_api_key = env("PS_API_KEY")
        self.proxies = env("PROXIES")
        self.auto_replace = env("AUTO_REPLACE", "1") == "1"
        self.replace_cooldown_hours = int(env("REPLACE_COOLDOWN_HOURS", "6"))
        self.expiry_warn_days = int(env("EXPIRY_WARN_DAYS", "3"))

        self.gemini_api_key = env("GEMINI_API_KEY")
        self.gemini_model = env("GEMINI_MODEL", "gemini-2.0-flash")

        self.xray_bin = Path(env("XRAY_BIN", str(ROOT / "bin" / "xray")))
        self.state_dir = Path(env("STATE_DIR", str(ROOT / "state")))
        self.workers = int(env("WORKERS", "5"))
        self.shift_minutes = int(env("SHIFT_MINUTES", "300"))
        self.check_every = int(env("CHECK_EVERY_SECONDS", "3600"))


settings = Settings()
