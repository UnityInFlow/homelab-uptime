"""Tests for uptime_check.py. No Internet access: HTTP checks run against a local server."""

from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uptime_check as u  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE_WEBHOOK = "https://hooks.slack.com/services/TEST/TEST/not-a-real-token"
NOW = 1_800_000_000.0  # fixed clock


# --------------------------------------------------------------------------- local HTTP server


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (stdlib API)
        if self.path == "/ok":
            self._reply(200, b"ok")
        elif self.path == "/fail":
            self._reply(503, b"down")
        elif self.path == "/missing":
            self._reply(404, b"nope")
        elif self.path.startswith("/hop"):
            hops = int(self.path[4:] or "0")
            if hops == 0:
                self._reply(200, b"arrived")
            else:
                self.send_response(301)
                self.send_header("Location", f"/hop{hops - 1}")
                self.send_header("Content-Length", "0")
                self.end_headers()
        elif self.path == "/to-internal":
            self.send_response(302)
            self.send_header("Location", "https://logs.home.unityinflow.com/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/to-ftp":
            self.send_response(302)
            self.send_header("Location", "ftp://example.org/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/slow":
            time.sleep(1.5)
            self._reply(200, b"late")
        else:
            self._reply(404, b"")

    def _reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


class LocalServer:
    def __enter__(self):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --------------------------------------------------------------------------- targets


class TargetsTest(unittest.TestCase):
    def test_public_urls_are_accepted(self):
        for url in ("https://jirihermann.com/", "https://keycloak.kotlinserversquad.com/realms/x",
                    "http://example.org/", "https://example.org:443/a"):
            self.assertEqual(u.validate_url(url), url)

    def test_urls_are_normalized(self):
        self.assertEqual(u.validate_url("HTTPS://Example.ORG"), "https://example.org/")
        self.assertEqual(u.validate_url("https://example.org/a?b=1#frag"), "https://example.org/a?b=1")

    def test_internal_and_unsafe_urls_are_refused(self):
        for url in ("https://hello.home.unityinflow.com/", "https://HELLO.HOME.unityinflow.com./",
                    "https://192.168.1.10/", "https://[::1]/", "http://localhost/", "https://intranet/",
                    "ftp://example.org/", "file:///etc/passwd", "https://user:pw@example.org/",
                    "https://example.org:8443/", "https://printer.local/", "not a url", "",
                    "https://a.example.org/x\n::warning::y", "https://a.example.org/a b", "https://a.example.org/\x7f",
                    "http://127.1/", "http://0x7f.1/", "https://home.unityinflow.com/", "https://home.arpa/",
                    "https://logs\u3002home.unityinflow.com/", "https://b\u00fccher.example/"):
            with self.subTest(url=url):
                with self.assertRaises(u.ConfigError) as caught:
                    u.validate_url(url)
                if url:
                    self.assertNotIn(url, str(caught.exception))
                    self.assertNotIn("home.unityinflow", str(caught.exception).lower())

    def test_load_targets_skips_comments_and_duplicates(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("# comment\n\nhttps://a.example.org/\n  https://b.example.org/x  \nhttps://a.example.org/\n")
        try:
            self.assertEqual(u.load_targets(handle.name), ["https://a.example.org/", "https://b.example.org/x"])
        finally:
            os.unlink(handle.name)

    def test_load_targets_names_the_bad_line(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("https://a.example.org/\nhttps://x.home.unityinflow.com/\n")
        try:
            with self.assertRaisesRegex(u.ConfigError, r" line 2: internal"):
                u.load_targets(handle.name)
        finally:
            os.unlink(handle.name)

    def test_repository_targets_are_public_https(self):
        targets = u.load_targets(os.path.join(REPO, "targets.txt"))
        self.assertTrue(targets)
        for url in targets:
            self.assertTrue(url.startswith("https://"), url)
            self.assertNotIn(".home.", url)

    def test_label(self):
        self.assertEqual(u.label("https://jirihermann.com/"), "jirihermann.com")
        self.assertEqual(u.label("https://Jirihermann.com/api/version?x=1#f"), "jirihermann.com/api/version")


# --------------------------------------------------------------------------- HTTP and TLS


class HttpTest(unittest.TestCase):
    def test_ok(self):
        with LocalServer() as srv:
            result = u.check_http_once(srv.base + "/ok", 5)
        self.assertTrue(result.ok)
        self.assertEqual(result.status, 200)

    def test_fake_failing_url(self):
        with LocalServer() as srv:
            result = u.check_http_once(srv.base + "/fail", 5)
        self.assertFalse(result.ok)
        self.assertEqual((result.status, result.problem), (503, "HTTP 503"))

    def test_redirects_followed_up_to_the_limit(self):
        with LocalServer() as srv:
            ok = u.check_http_once(srv.base + f"/hop{u.MAX_REDIRECTS - 1}", 5, public_only=False)
            too_many = u.check_http_once(srv.base + f"/hop{u.MAX_REDIRECTS + 2}", 5, public_only=False)
        self.assertTrue(ok.ok)
        self.assertFalse(too_many.ok)
        self.assertEqual(too_many.status, 301)

    def test_redirect_to_internal_or_non_http_is_refused(self):
        with LocalServer() as srv:
            internal = u.check_http_once(srv.base + "/to-internal", 5)
            ftp = u.check_http_once(srv.base + "/to-ftp", 5, public_only=False)
        self.assertEqual((internal.ok, internal.problem), (False, "redirect to a non-public URL"))
        self.assertEqual((ftp.ok, ftp.problem), (False, "redirect to a non-http URL"))

    def test_name_with_non_public_address_is_refused(self):
        self.assertEqual(u.resolution_problem("localhost"), "name resolves to a non-public address")
        result = u.check_http("https://a.example.org/", 5, once=lambda *a: self.fail("requested"),
                              resolve=lambda host: "name resolves to a non-public address")
        self.assertEqual((result.ok, result.problem), (False, "name resolves to a non-public address"))

    def test_slow_answer_is_a_timeout(self):
        with LocalServer() as srv:
            result = u.check_http_once(srv.base + "/slow", 0.5)
        self.assertFalse(result.ok)
        self.assertTrue(result.problem.startswith("timeout"), result.problem)

    def test_connection_refused(self):
        result = u.check_http_once(f"http://127.0.0.1:{closed_port()}/", 2)
        self.assertFalse(result.ok)
        self.assertEqual(result.problem, "connection refused")

    def test_retry_once_after_failure(self):
        calls = []

        def once(url, timeout):
            calls.append(url)
            return u.HttpResult(ok=len(calls) > 1, status=200 if len(calls) > 1 else 502,
                                problem=None if len(calls) > 1 else "HTTP 502", elapsed=0.1)

        result = u.check_http("https://a.example.org/", 5, once=once, sleep=lambda _: None, resolve=lambda h: None)
        self.assertTrue(result.ok)
        self.assertEqual(len(calls), 2)

    def test_no_retry_when_ok(self):
        calls = []

        def once(url, timeout):
            calls.append(url)
            return u.HttpResult(ok=True, status=200, problem=None, elapsed=0.1)

        u.check_http("https://a.example.org/", 5, once=once, sleep=lambda _: self.fail("slept"), resolve=lambda h: None)
        self.assertEqual(len(calls), 1)

    def test_classify_error(self):
        import ssl
        import urllib.error
        self.assertEqual(u.classify_error(socket.timeout()), "timeout")
        self.assertEqual(u.classify_error(socket.gaierror(-2, "x")), "DNS lookup failed")
        self.assertEqual(u.classify_error(urllib.error.URLError(socket.gaierror(-2, "x"))), "DNS lookup failed")
        self.assertEqual(u.classify_error(ssl.SSLCertVerificationError("x")), "TLS certificate not valid")
        self.assertEqual(u.classify_error(urllib.error.URLError("10.0.0.1 said no")), "connection error")


class CertTest(unittest.TestCase):
    def test_days_until_parses_openssl_dates(self):
        not_after = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(NOW + 30 * 86400 + 3600))
        self.assertEqual(u.days_until(not_after, NOW), 30)
        not_after = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(NOW - 3600))
        self.assertEqual(u.days_until(not_after, NOW), -1)
        self.assertEqual(u.days_until("Jun  1 12:00:00 2027 GMT", u.ssl.cert_time_to_seconds("May 31 12:00:00 2027 GMT")), 1)

    def test_threshold_is_more_than_min_days(self):
        self.assertTrue(u.cert_result(15, 14).ok)
        self.assertFalse(u.cert_result(14, 14).ok)
        self.assertEqual(u.cert_result(9, 14).problem, "certificate expires in 9 days")
        self.assertEqual(u.cert_result(-1, 14).problem, "certificate expired")

    def test_unreadable_certificate_is_unknown(self):
        result = u.check_cert("127.0.0.1", 2, 14, now=NOW, port=closed_port(), resolve=lambda h: None)
        self.assertIsNone(result.ok)
        self.assertIn("connection refused", result.problem)

    def test_no_certificate_probe_to_non_public_addresses(self):
        result = u.check_cert("localhost", 2, 14, now=NOW, port=closed_port())
        self.assertIsNone(result.ok)
        self.assertEqual(result.problem, "certificate not readable (name resolves to a non-public address)")


# --------------------------------------------------------------------------- state changes


def chk(key, ok, detail="x"):
    name = u.label(key.split(" ", 1)[1]) if key.startswith("http ") else key.split(" ", 1)[1]
    return u.Check(key=key, name=name, ok=ok, detail=detail)


A = "http https://a.example.org/"
B = "http https://b.example.org/api"
CA = "cert a.example.org"


class EventsTest(unittest.TestCase):
    def test_first_run_reports_only_failures(self):
        new, events = u.compute_events(None, [chk(A, True), chk(B, False, "HTTP 503"), chk(CA, True)])
        self.assertEqual(new, {A: "ok", B: "fail", CA: "ok"})
        self.assertEqual(events, [(B, ":red_circle: DOWN b.example.org/api: HTTP 503")])

    def test_up_to_down_and_back(self):
        prev = {"version": 1, "checks": {A: "ok"}}
        _, events = u.compute_events(prev, [chk(A, False, "timeout")])
        self.assertEqual(events, [(A, ":red_circle: DOWN a.example.org: timeout")])
        prev = {"version": 1, "checks": {A: "fail"}}
        _, events = u.compute_events(prev, [chk(A, True, "HTTP 200")])
        self.assertEqual(events, [(A, ":large_green_circle: RECOVERED a.example.org: HTTP 200")])

    def test_no_message_without_change(self):
        prev = {"version": 1, "checks": {A: "fail", CA: "ok"}}
        _, events = u.compute_events(prev, [chk(A, False, "HTTP 502"), chk(CA, True)])
        self.assertEqual(events, [])

    def test_cert_ok_to_expiring_and_renewed(self):
        prev = {"version": 1, "checks": {CA: "ok"}}
        _, events = u.compute_events(prev, [chk(CA, False, "certificate expires in 9 days")])
        self.assertEqual(events, [(CA, ":warning: CERT a.example.org: certificate expires in 9 days")])
        prev = {"version": 1, "checks": {CA: "fail"}}
        _, events = u.compute_events(prev, [chk(CA, True, "89 days left")])
        self.assertEqual(events, [(CA, ":large_green_circle: CERT OK a.example.org: 89 days left")])

    def test_unknown_result_keeps_previous_value(self):
        prev = {"version": 1, "checks": {CA: "fail"}}
        new, events = u.compute_events(prev, [chk(CA, None)])
        self.assertEqual((new, events), ({CA: "fail"}, []))
        new, events = u.compute_events(None, [chk(CA, None)])
        self.assertEqual((new, events), ({}, []))

    def test_new_target_that_is_up_is_silent(self):
        prev = {"version": 1, "checks": {A: "ok"}}
        new, events = u.compute_events(prev, [chk(A, True), chk(B, True)])
        self.assertEqual(events, [])
        self.assertEqual(new[B], "ok")

    def test_removed_failing_target_is_reported_once(self):
        prev = {"version": 1, "checks": {A: "ok", B: "fail"}}
        new, events = u.compute_events(prev, [chk(A, True)])
        self.assertEqual(events, [(B, ":white_circle: REMOVED b.example.org/api: no longer checked (was failing)")])
        self.assertNotIn(B, new)
        prev = {"version": 1, "checks": {A: "ok", B: "ok"}}
        _, events = u.compute_events(prev, [chk(A, True)])
        self.assertEqual(events, [])


class KeepaliveTest(unittest.TestCase):
    def at(self, days):
        return NOW - days * 86400 - 60

    def test_no_reminder_before_day_50(self):
        st, msg, age = u.keepalive_event(None, "s1", int(self.at(49)), NOW)
        self.assertIsNone(msg)
        self.assertEqual((st, age), ({"sha": "s1", "level": 0}, 49))

    def test_reminders_at_50_and_57_once_each(self):
        st, msg, _ = u.keepalive_event(None, "s1", int(self.at(50)), NOW)
        self.assertIn("50 days old", msg)
        prev = {"version": 1, "checks": {}, "keepalive": st}
        st2, msg, _ = u.keepalive_event(prev, "s1", int(self.at(51)), NOW)
        self.assertIsNone(msg)
        prev = {"version": 1, "checks": {}, "keepalive": st2}
        st3, msg, _ = u.keepalive_event(prev, "s1", int(self.at(57)), NOW)
        self.assertIn("57 days old", msg)
        self.assertEqual(st3["level"], 57)

    def test_new_commit_resets(self):
        prev = {"version": 1, "checks": {}, "keepalive": {"sha": "s1", "level": 57}}
        st, msg, age = u.keepalive_event(prev, "s2", int(self.at(1)), NOW)
        self.assertIsNone(msg)
        self.assertEqual(st, {"sha": "s2", "level": 0})

    def test_without_commit_info_nothing_happens(self):
        prev = {"version": 1, "checks": {}, "keepalive": {"sha": "s1", "level": 50}}
        st, msg, age = u.keepalive_event(prev, None, None, NOW)
        self.assertEqual((st, msg, age), ({"sha": "s1", "level": 50}, None, None))


class MessageTest(unittest.TestCase):
    def test_escaping_and_link(self):
        payload = u.build_message(["DOWN a<b>&c"], "https://github.com/o/r/actions/runs/1")
        self.assertEqual(payload["text"], "DOWN a&lt;b&gt;&amp;c\n<https://github.com/o/r/actions/runs/1|details>")
        self.assertFalse(payload["unfurl_links"])


# --------------------------------------------------------------------------- end to end (fakes)


class MainTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.targets = os.path.join(self.dir.name, "targets.txt")
        with open(self.targets, "w") as handle:
            handle.write("https://a.example.org/\nhttps://b.example.org/api\n")
        self.state = os.path.join(self.dir.name, "state", "state.json")
        self.summary = os.path.join(self.dir.name, "summary.md")
        self.down: set[str] = set()
        self.cert_days = 60
        self.cert_unreadable = False
        self.cert_hosts: list[str] = []
        self.posts: list[dict] = []
        self.post_ok = True
        env = {k: v for k, v in os.environ.items()
               if k not in ("SLACK_WEBHOOK_URL", "GITHUB_ACTIONS", "GITHUB_EVENT_PATH", "GITHUB_STEP_SUMMARY")}
        env["SLACK_WEBHOOK_URL"] = FAKE_WEBHOOK
        patcher = unittest.mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def http(self, url, timeout):
        if url in self.down:
            return u.HttpResult(ok=False, status=503, problem="HTTP 503", elapsed=0.1)
        return u.HttpResult(ok=True, status=200, problem=None, elapsed=0.1)

    def cert(self, host, timeout, min_days, now):
        self.cert_hosts.append(host)
        if self.cert_unreadable:
            return u.CertResult(ok=None, days=None, problem="certificate not readable (timeout)")
        return u.cert_result(self.cert_days, min_days)

    def post(self, webhook, payload):
        self.assertEqual(webhook, FAKE_WEBHOOK)
        self.posts.append(payload)
        return self.post_ok

    def run_main(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = u.main(["--targets", self.targets, "--state", self.state, "--summary", self.summary, *extra],
                        http_fn=self.http, cert_fn=self.cert, post_fn=self.post, now=NOW)
        self.assertNotIn("not-a-real-token", out.getvalue() + err.getvalue())
        return rc, out.getvalue(), err.getvalue()

    def test_all_ok_first_run_is_silent(self):
        rc, out, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertEqual(self.posts, [])
        self.assertEqual(len([line for line in out.splitlines() if line.startswith("OK  ")]), 2)
        with open(self.state) as handle:
            self.assertEqual(json.load(handle)["checks"]["http https://a.example.org/"], "ok")
        with open(self.summary) as handle:
            self.assertIn("| OK | `b.example.org/api` |", handle.read())

    def test_down_then_still_down_then_recovered(self):
        self.run_main()
        self.down = {"https://b.example.org/api"}
        rc, out, _ = self.run_main()
        self.assertEqual(rc, 1)
        self.assertIn("FAIL  b.example.org/api  HTTP 503", out)
        self.assertEqual(len(self.posts), 1)
        self.assertIn("DOWN b.example.org/api: HTTP 503", self.posts[0]["text"])
        rc, _, _ = self.run_main()
        self.assertEqual((rc, len(self.posts)), (1, 1))
        self.down = set()
        rc, _, _ = self.run_main()
        self.assertEqual((rc, len(self.posts)), (0, 2))
        self.assertIn("RECOVERED b.example.org/api", self.posts[1]["text"])

    def test_cert_expiring_fails_and_notifies_once_per_host(self):
        self.run_main()
        self.cert_days = 10
        rc, _, _ = self.run_main()
        self.assertEqual(rc, 1)
        self.assertEqual(self.posts[0]["text"].count("CERT"), 2)  # two hosts
        self.assertIn("certificate expires in 10 days", self.posts[0]["text"])

    def test_failed_delivery_is_retried_next_run(self):
        self.run_main()
        self.down = {"https://a.example.org/"}
        self.post_ok = False
        _, _, err = self.run_main()
        self.assertIn("Slack", err)
        self.post_ok = True
        self.run_main()
        self.assertEqual(len(self.posts), 2)
        self.assertIn("DOWN a.example.org", self.posts[1]["text"])
        self.run_main()
        self.assertEqual(len(self.posts), 2)

    def test_failed_delivery_on_first_run_is_retried(self):
        self.down = {"https://a.example.org/"}
        self.post_ok = False
        self.run_main()
        self.post_ok = True
        self.run_main()
        self.assertEqual(len(self.posts), 2)

    def test_without_webhook_the_run_still_fails_and_warns(self):
        del os.environ["SLACK_WEBHOOK_URL"]
        self.down = {"https://a.example.org/"}
        rc, _, err = self.run_main()
        self.assertEqual(rc, 1)
        self.assertEqual(self.posts, [])
        self.assertIn("SLACK_WEBHOOK_URL is not set", err)
        with open(self.summary) as handle:
            self.assertIn("secret SLACK_WEBHOOK_URL is not set", handle.read())

    def test_unexpected_webhook_format_is_not_used(self):
        os.environ["SLACK_WEBHOOK_URL"] = "https://attacker.example.org/hook"
        self.down = {"https://a.example.org/"}
        _, out, err = self.run_main()
        self.assertEqual(self.posts, [])
        self.assertNotIn("attacker", out + err)

    def test_extra_url_down_then_removed(self):
        self.run_main()
        rc, _, _ = self.run_main("--extra-url", "https://a.example.org/missing")
        self.assertEqual(rc, 0)  # the fake answers 200 for it
        self.down = {"https://a.example.org/missing"}
        rc, _, _ = self.run_main("--extra-url", "https://a.example.org/missing")
        self.assertEqual(rc, 1)
        self.assertIn("DOWN a.example.org/missing", self.posts[-1]["text"])
        rc, _, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertIn("REMOVED a.example.org/missing", self.posts[-1]["text"])

    def test_internal_extra_url_is_refused(self):
        rc, out, err = self.run_main("--extra-url", "https://logs.home.unityinflow.com/")
        self.assertEqual(rc, 2)
        self.assertIn("internal", err)
        self.assertNotIn("logs.home", out + err)

    def test_unreadable_certificate_fails_when_the_site_answers(self):
        self.run_main()
        self.cert_unreadable = True
        rc, _, _ = self.run_main()
        self.assertEqual(rc, 1)
        self.assertIn("CERT a.example.org: certificate not readable (timeout)", self.posts[-1]["text"])

    def test_unreadable_certificate_of_a_down_host_is_not_a_second_message(self):
        self.run_main()
        self.cert_unreadable = True
        self.down = {"https://a.example.org/"}
        self.run_main()
        self.assertIn("DOWN a.example.org", self.posts[-1]["text"])
        self.assertNotIn("CERT a.example.org", self.posts[-1]["text"])

    def test_uppercase_scheme_still_checks_the_certificate(self):
        with open(self.targets, "w") as handle:
            handle.write("HTTPS://A.Example.org/\n")
        self.run_main()
        self.assertEqual(self.cert_hosts, ["a.example.org"])

    def test_missing_webhook_keeps_messages_pending(self):
        del os.environ["SLACK_WEBHOOK_URL"]
        self.run_main()
        self.down = {"https://a.example.org/"}
        self.run_main()
        os.environ["SLACK_WEBHOOK_URL"] = FAKE_WEBHOOK
        self.run_main()
        self.assertEqual(len(self.posts), 1)
        self.assertIn("DOWN a.example.org: HTTP 503 (detected ", self.posts[0]["text"])

    def test_outage_that_ends_before_delivery_is_still_reported(self):
        self.run_main()
        self.down = {"https://a.example.org/"}
        self.post_ok = False
        self.run_main()
        self.down = set()
        self.post_ok = True
        self.run_main()
        text = self.posts[-1]["text"]
        self.assertIn("DOWN a.example.org: HTTP 503 (detected ", text)
        self.assertIn("RECOVERED a.example.org", text)
        self.assertLess(text.index("DOWN"), text.index("RECOVERED"))
        self.run_main()
        self.assertEqual(len(self.posts), 2)

    def test_pending_queue_is_capped(self):
        del os.environ["SLACK_WEBHOOK_URL"]
        self.run_main()
        for _ in range(u.MAX_PENDING):
            self.down = {"https://a.example.org/"}
            self.run_main()
            self.down = set()
            self.run_main()
        with open(self.state) as handle:
            self.assertEqual(len(json.load(handle)["pending"]), u.MAX_PENDING)
        os.environ["SLACK_WEBHOOK_URL"] = FAKE_WEBHOOK
        self.run_main()
        self.assertTrue(self.posts[-1]["text"].startswith(f"({u.MAX_PENDING} older undelivered messages dropped)"))
        with open(self.state) as handle:
            self.assertNotIn("pending_dropped", json.load(handle))

    def write_event(self, event):
        path = os.path.join(self.dir.name, "event.json")
        with open(path, "w") as handle:
            json.dump(event, handle)
        os.environ["GITHUB_EVENT_PATH"] = path

    def test_extra_url_from_the_dispatch_event(self):
        self.write_event({"inputs": {"extra_url": "https://c.example.org/x"}})
        self.down = {"https://c.example.org/x"}
        rc, out, _ = self.run_main("--extra-url-from-event")
        self.assertEqual(rc, 1)
        self.assertIn("FAIL  c.example.org/x", out)

    def test_extra_url_from_event_without_input(self):
        for event in ({"schedule": "*/15 * * * *"}, {"inputs": {"extra_url": ""}}, {"inputs": None}):
            with self.subTest(event=event):
                self.write_event(event)
                rc, out, _ = self.run_main("--extra-url-from-event")
                self.assertEqual(rc, 0)
                self.assertEqual(out.count("OK  "), 2)

    def test_rejected_extra_url_from_event_is_not_printed(self):
        self.write_event({"inputs": {"extra_url": "https://vault.home.unityinflow.com/"}})
        rc, out, err = self.run_main("--extra-url-from-event")
        self.assertEqual(rc, 2)
        self.assertNotIn("vault", out + err)

    def test_keepalive_reminder_sent_once(self):
        head_time = str(int(NOW - 52 * 86400))
        self.run_main("--head-sha", "abc", "--head-time", head_time)
        self.run_main("--head-sha", "abc", "--head-time", head_time)
        self.assertEqual(len(self.posts), 1)
        self.assertIn("KEEPALIVE", self.posts[0]["text"])

    def test_no_notify(self):
        self.down = {"https://a.example.org/"}
        rc, _, _ = self.run_main("--no-notify")
        self.assertEqual((rc, self.posts), (1, []))

    def test_corrupt_state_is_a_first_run(self):
        os.makedirs(os.path.dirname(self.state))
        with open(self.state, "w") as handle:
            handle.write("{not json")
        rc, _, err = self.run_main()
        self.assertEqual(rc, 0)
        self.assertIn("unreadable", err)


if __name__ == "__main__":
    unittest.main()
