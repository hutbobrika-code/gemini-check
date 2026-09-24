import unittest

from monitor import report, state
from monitor.model import BLOCKED, CAPTCHA, DEGRADED, DOWN, OK, Point, Result, overall
from monitor.probes import NAMES, parse_target
from monitor.telegram import split


def node(name, status=OK, note="", **services):
    everything = {sid: Result(OK) for sid in NAMES}
    everything.update(services)
    point = Point("node", name, country="NL", note=note, services=everything)
    point.status = status if status == DOWN else overall(everything)
    return point


class ConfirmTest(unittest.TestCase):
    def test_change_needs_two_checks_in_a_row(self):
        before, pending = {"a": OK}, {}
        self.assertEqual(state.confirm(before, {"a": DOWN}, pending), {"a": OK})
        self.assertEqual(state.confirm(before, {"a": DOWN}, pending), {"a": DOWN})
        self.assertEqual(pending, {})

    def test_single_blip_is_forgotten(self):
        before, pending = {"a": OK}, {}
        state.confirm(before, {"a": DOWN}, pending)
        self.assertEqual(state.confirm(before, {"a": OK}, pending), {"a": OK})
        self.assertEqual(pending, {})

    def test_new_key_is_taken_at_once(self):
        self.assertEqual(state.confirm({}, {"b": BLOCKED}, {}), {"b": BLOCKED})


class ChangesTest(unittest.TestCase):
    def test_no_changes_means_no_message(self):
        points = [node("Польша")]
        snap = state.snapshot(points)
        self.assertEqual(report.changes_report(points, snap, snap), "")

    def test_service_transitions_are_grouped(self):
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

    def test_new_healthy_point_is_not_news(self):
        points = [node("Польша"), node("Индия")]
        before = state.snapshot(points[:1])
        self.assertEqual(report.changes_report(points, before, state.snapshot(points)), "")


class StatusReportTest(unittest.TestCase):
    def test_sections(self):
        points = [node("🇵🇱 Польша"), node("🇭🇰 Гонконг", chatgpt=Result(BLOCKED))]
        text = report.status_report(points, "📊 Статус")
        self.assertIn("Узлы подписки: <b>1 из 2</b> без замечаний", text)
        self.assertIn("🚫 регион: ChatGPT", text)
        self.assertIn("Без замечаний — 1 точка", text)
        self.assertIn("🚫 Гонконг", text)


class HelpersTest(unittest.TestCase):
    def test_plural(self):
        self.assertEqual(report.plural(1, "точка", "точки", "точек"), "1 точка")
        self.assertEqual(report.plural(3, "точка", "точки", "точек"), "3 точки")
        self.assertEqual(report.plural(11, "точка", "точки", "точек"), "11 точек")
        self.assertEqual(report.plural(21, "точка", "точки", "точек"), "21 точка")

    def test_parse_target(self):
        self.assertEqual(parse_target("youtube.com"), "https://youtube.com")
        self.assertEqual(parse_target("http://a.b/c"), "http://a.b/c")
        self.assertIsNone(parse_target("не адрес"))
        self.assertIsNone(parse_target("ftp://x"))

    def test_split_keeps_quotes_whole(self):
        lines = "\n".join(f"строка {i}" for i in range(900))
        quote = f"<blockquote expandable>{lines}</blockquote>"
        parts = split("заголовок\n\n" + quote + "\n\nподвал", limit=1000)
        self.assertGreater(len(parts), 1)
        for part in parts:
            self.assertLessEqual(len(part), 1000)
            self.assertEqual(part.count("<blockquote"), part.count("</blockquote>"))
        self.assertEqual(sum(p.count("строка") for p in parts), 900)


if __name__ == "__main__":
    unittest.main()
