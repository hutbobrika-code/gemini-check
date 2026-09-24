import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

# через curl: он сам умеет socks5 и отдаёт всю цепочку редиректов
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")


@dataclass
class Response:
    code: int  # 0 если ответа не было
    url: str  # где закончились редиректы
    body: str = ""
    size: int = 0
    headers: str = ""
    seconds: float = 0.0


def fetch(url, proxy=None, timeout=20, follow=False, headers=(), data=None):
    with tempfile.TemporaryDirectory() as tmp:
        body_file = Path(tmp, "body")
        head_file = Path(tmp, "head")
        cmd = ["curl", "-sS", "-m", str(timeout), "-A", UA,
               "-o", str(body_file), "-D", str(head_file), "-w", "%{json}"]
        if follow:
            cmd += ["-L", "--max-redirs", "5"]
        if proxy:
            cmd += ["-x", proxy]
        for h in headers:
            cmd += ["-H", h]
        if data is not None:
            cmd += ["--data", data]
        cmd.append(url)

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
            info = json.loads(res.stdout or "{}")
        except (subprocess.SubprocessError, ValueError):
            return Response(0, url)

        head = read(head_file, 16384)
        code = int(info.get("http_code") or 0)
        final = info.get("url_effective") or url
        if 300 <= code < 400:
            final = redirect_target(head) or final
        return Response(code, final, read(body_file, 4096), int(info.get("size_download") or 0),
                        head.lower(), float(info.get("time_total") or 0))


def read(path, limit):
    try:
        return path.read_bytes()[:limit].decode("utf-8", "replace")
    except OSError:
        return ""


def redirect_target(headers):
    # если по дороге была капча гугла, то итог это она, а не последний редирект
    # (там петля капча -> сайт -> капча, и по последнему location её не видно)
    locations = [line.split(":", 1)[1].strip() for line in headers.splitlines()
                 if line.lower().startswith("location:")]
    for loc in locations:
        if "/sorry/" in loc:
            return loc
    return locations[-1] if locations else ""
