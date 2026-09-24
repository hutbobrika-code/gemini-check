import unittest

from monitor import report, state
from monitor.model import BLOCKED, CAPTCHA, DEGRADED, DOWN, OK, Point, Result, overall
from monitor.probes import NAMES, parse_target
from monitor.telegram import split


def node(name, status=OK, note="", **services):
    s = {sid: Result(OK) for sid in NAMES}
    s.update(services)
    p = Point("node", name, country="NL", note=note, services=s)
    p.status = DOWN if status == DOWN else overall(s)
    return p


class TestConfirm(unittest.TestCase):
    def test_needs_two_checks(self):
        before, pending = {"a": OK}, {}
        self.assertEqual(state.confirm(before, {"a": DOWN}, pending), {"a": OK})
        self.assertEqual(state.confirm(before, {"a": DOWN}, pending), {"a": DOWN})
        self.assertEqual(pending, {})

    def test_blip_forgotten(self):
        before, pending = {"a": OK}, {}
        state.confirm(before, {"a": DOWN}, pending)
        self.assertEqual(state.confirm(before, {"a": OK}, pending), {"a": OK})
        self.assertEqual(pending, {})

    def test_new_key(self):
        self.assertEqual(state.confirm({}, {"b": BLOCKED}, {}), {"b": BLOCKED})


class TestChanges(unittest.TestCase):
    def test_nothing_changed(self):
        points = [node("Польша")]
        snap = state.snapshot(points)
        self.assertEqual(report.changes_report(points, snap, snap), "")

    def test_grouped(self):
        before = state.snapshot([node("Германия")])
        points = [node("Германия", chatgpt=Result(DOWN), twitch=Result(DOWN),
                       gemini=Result(DEGRADED, CAPTCHA))]
        text = report.changes_report(points, before, state.snapshot(points))
        self.assertIn("🔴 Изменения", text)
        self.assertIn("✅ → ❌  ChatGPT, Twitch", text)
        self.assertIn("✅ → ⚠️  Gemini (капча Google)", text)

    def test_recovery(self):
        before = state.snapshot([node("Польша", DOWN, "хост не отвечает")])
        points = [node("Польша")]
        text = report.changes_report(points, before, state.snapshot(points))
        self.assertIn("🟢 Восстановление", text)
        self.assertIn("снова работает", text)

    def test_new_ok_point_ignored(self):
        points = [node("Польша"), node("Индия")]
        before = state.snapshot(points[:1])
        self.assertEqual(report.changes_report(points, before, state.snapshot(points)), "")


class TestStatusReport(unittest.TestCase):
    def test_sections(self):
        points = [node("🇵🇱 Польша"), node("🇭🇰 Гонконг", chatgpt=Result(BLOCKED))]
        text = report.status_report(points, "📊 Статус")
        self.assertIn("Узлы подписки: <b>1 из 2</b> без замечаний", text)
        self.assertIn("🚫 регион: ChatGPT", text)
        self.assertIn("Без замечаний — 1 точка", text)
        self.assertIn("🚫 Гонконг", text)


class TestHelpers(unittest.TestCase):
    def test_plural(self):
        words = ("точка", "точки", "точек")
        self.assertEqual(report.plural(1, *words), "1 точка")
        self.assertEqual(report.plural(3, *words), "3 точки")
        self.assertEqual(report.plural(11, *words), "11 точек")
        self.assertEqual(report.plural(21, *words), "21 точка")

    def test_parse_target(self):
        self.assertEqual(parse_target("youtube.com"), "https://youtube.com")
        self.assertEqual(parse_target("http://a.b/c"), "http://a.b/c")
        self.assertIsNone(parse_target("не адрес"))
        self.assertIsNone(parse_target("ftp://x"))

    def test_split_quote(self):
        lines = "\n".join(f"строка {i}" for i in range(900))
        text = f"заголовок\n\n<blockquote expandable>{lines}</blockquote>\n\nподвал"
        parts = split(text, limit=1000)
        self.assertGreater(len(parts), 1)
        for part in parts:
            self.assertLessEqual(len(part), 1000)
            self.assertEqual(part.count("<blockquote"), part.count("</blockquote>"))
        self.assertEqual(sum(p.count("строка") for p in parts), 900)


if __name__ == "__main__":
    unittest.main()
