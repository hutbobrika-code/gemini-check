"""HTTP через прокси. Берём curl: он умеет SOCKS5 без сторонних библиотек
и отдаёт всю цепочку редиректов."""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")


@dataclass
class Response:
    code: int                  # 0 — ответа не было
    url: str                   # где закончились редиректы
    body: str = ""             # начало тела
    size: int = 0
    headers: str = ""          # в нижнем регистре
    seconds: float = 0.0


def fetch(url: str, proxy: str | None = None, *, timeout: int = 20, follow: bool = False,
          headers: tuple[str, ...] | list[str] = (), data: str | None = None) -> Response:
    with tempfile.TemporaryDirectory() as tmp:
        body_file, head_file = Path(tmp, "body"), Path(tmp, "head")
        cmd = ["curl", "-sS", "-m", str(timeout), "-A", BROWSER,
               "-o", str(body_file), "-D", str(head_file), "-w", "%{json}"]
        if follow:
            cmd += ["-L", "--max-redirs", "5"]
        if proxy:
            cmd += ["-x", proxy]
        for header in headers:
            cmd += ["-H", header]
        if data is not None:
            cmd += ["--data", data]
        cmd.append(url)

        try:
            done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
            info = json.loads(done.stdout or "{}")
        except (subprocess.SubprocessError, ValueError):
            return Response(0, url)

        head = _read(head_file, 16_384)
        code = int(info.get("http_code") or 0)
        final = info.get("url_effective") or url
        if 300 <= code < 400:
            final = _redirect_target(head) or final
        return Response(code, final, _read(body_file, 4096), int(info.get("size_download") or 0),
                        head.lower(), float(info.get("time_total") or 0))


def _read(path: Path, limit: int) -> str:
    try:
        return path.read_bytes()[:limit].decode("utf-8", "replace")
    except OSError:
        return ""


def _redirect_target(headers: str) -> str:
    """Куда вела цепочка, на которой curl остановился. Если по дороге была
    капча Google, ответ — она: иначе петля выглядит как редирект сайта на себя."""
    targets = [line.split(":", 1)[1].strip() for line in headers.splitlines()
               if line.lower().startswith("location:")]
    for target in targets:
        if "/sorry/" in target:
            return target
    return targets[-1] if targets else ""
