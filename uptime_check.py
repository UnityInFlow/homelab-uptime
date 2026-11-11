#!/usr/bin/env python3
"""External uptime check for the homelab's public sites (Python 3.10+, standard library only).

For every URL in the targets file: HTTP GET must end with status 200 within the timeout (at most
MAX_REDIRECTS redirects are followed; the final status is recorded), and for https targets the
host's TLS certificate must be valid for more than --cert-min-days days.

Prints one line per target, writes a Markdown job summary when $GITHUB_STEP_SUMMARY (or
--summary) is set, and exits 1 if any target fails (2 on a usage or configuration error).

Slack: the webhook URL is read only from the environment variable SLACK_WEBHOOK_URL and is never
printed. One message is sent per run, and only when a state changes (up -> down, down -> up,
certificate ok -> expiring and back, a failing target removed from the list) or the keepalive
reminder is due. Without a previous state file only failures are sent. If the message cannot be
delivered, the changed states are not stored, so the next run tries again.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

USER_AGENT = "homelab-uptime/1 (+https://github.com/UnityInFlow/homelab-uptime)"
MAX_REDIRECTS = 3
MAX_BODY_BYTES = 1024 * 1024
RETRY_DELAY_SECONDS = 5.0
STATE_VERSION = 1
SLACK_PREFIX = "https://hooks.slack.com/"
# GitHub disables scheduled workflows of a public repository after 60 days without repository
# activity. Reminders go out once the last commit on the default branch is this many days old.
DISABLE_AFTER_DAYS = 60
KEEPALIVE_REMIND_DAYS = (50, 57)
# Names that must never be checked from the Internet (internal-only zones).
INTERNAL_SUFFIXES = (".home.unityinflow.com", ".local", ".lan", ".internal", ".localhost", ".home.arpa")


class ConfigError(Exception):
    """Invalid targets file, URL or arguments."""


# --------------------------------------------------------------------------- targets


def validate_url(url: str) -> str:
    """Return the URL if it is an absolute http(s) URL of a public DNS name, else raise ConfigError."""
    url = url.strip()
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ConfigError(f"not a valid URL: {url!r}") from exc
    if parts.scheme not in ("http", "https"):
        raise ConfigError(f"only http and https URLs are allowed: {url!r}")
    if parts.username is not None or parts.password is not None:
        raise ConfigError(f"credentials in URLs are not allowed: {url!r}")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise ConfigError(f"URL without a host name: {url!r}")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ConfigError(f"IP addresses are not allowed, use a public DNS name: {url!r}")
    if "." not in host or host == "localhost" or host.endswith(INTERNAL_SUFFIXES):
        raise ConfigError(f"internal or single-label host names are not allowed: {url!r}")
    if port is not None and port not in (80, 443):
        raise ConfigError(f"only the default ports 80 and 443 are allowed: {url!r}")
    return url


def load_targets(path: str) -> list[str]:
    """Read one URL per line; blank lines and lines starting with '#' are ignored."""
    targets: list[str] = []
    with open(path, encoding="utf-8") as handle:
        for number, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                url = validate_url(line)
            except ConfigError as exc:
                raise ConfigError(f"{path}:{number}: {exc}") from None
            if url not in targets:
                targets.append(url)
    if not targets:
        raise ConfigError(f"{path}: no targets")
    return targets


def label(url: str) -> str:
    """Short public name for messages: host plus path, without scheme, query or fragment."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    path = parts.path if parts.path not in ("", "/") else ""
    return host + path


def host_of(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


# --------------------------------------------------------------------------- checks


@dataclass
class HttpResult:
    ok: bool
    status: Optional[int]
    problem: Optional[str]
    elapsed: float


@dataclass
class CertResult:
    # ok: True = valid long enough, False = expiring soon, None = could not be read (unknown)
    ok: Optional[bool]
    days: Optional[int]
    problem: Optional[str]


def classify_error(exc: BaseException) -> str:
    """Map a network exception to a short public description (no addresses, no raw messages)."""
    if isinstance(exc, urllib.error.URLError) and not isinstance(exc, urllib.error.HTTPError):
        reason = exc.reason
        if isinstance(reason, BaseException):
            return classify_error(reason)
        return "connection error"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "TLS certificate not valid"
    if isinstance(exc, ssl.SSLError):
        return "TLS error"
    if isinstance(exc, socket.gaierror):
        return "DNS lookup failed"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, ConnectionResetError):
        return "connection reset"
    return "connection error"


class _LimitedRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 (stdlib API)
        scheme = urllib.parse.urlsplit(newurl).scheme
        if scheme not in ("http", "https"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    return urllib.request.build_opener(_LimitedRedirects(), urllib.request.HTTPSHandler(context=context))


def check_http_once(url: str, timeout: float) -> HttpResult:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"}, method="GET")
    start = time.monotonic()
    status: Optional[int] = None
    problem: Optional[str] = None
    try:
        with _opener().open(request, timeout=timeout) as response:
            status = response.status
            remaining = MAX_BODY_BYTES
            while remaining > 0 and time.monotonic() - start <= timeout:
                chunk = response.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
    except Exception as exc:  # noqa: BLE001 - any network failure is a "down" result
        problem = classify_error(exc)
    elapsed = time.monotonic() - start
    if problem is None and status != 200:
        problem = f"HTTP {status}"
    if problem is None and elapsed > timeout:
        problem = f"timeout (answered after {elapsed:.0f} s)"
    return HttpResult(ok=problem is None, status=status, problem=problem, elapsed=elapsed)


def check_http(url: str, timeout: float, retry_delay: float = RETRY_DELAY_SECONDS,
               once: Callable[[str, float], HttpResult] = check_http_once,
               sleep: Callable[[float], None] = time.sleep) -> HttpResult:
    """One retry after a short pause, so a single dropped request does not page anyone."""
    result = once(url, timeout)
    if result.ok:
        return result
    sleep(retry_delay)
    return once(url, timeout)


def days_until(not_after: str, now: float) -> int:
    """Whole days from now until an OpenSSL notAfter string ('Jun  1 12:00:00 2026 GMT')."""
    expires = ssl.cert_time_to_seconds(not_after)
    return int((expires - now) // 86400)


def check_cert(host: str, timeout: float, min_days: int, now: Optional[float] = None,
               port: int = 443) -> CertResult:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        days = days_until(cert["notAfter"], time.time() if now is None else now)
    except Exception as exc:  # noqa: BLE001 - unknown; the HTTP check reports connectivity/TLS failures
        return CertResult(ok=None, days=None, problem=f"certificate not readable ({classify_error(exc)})")
    return cert_result(days, min_days)


def cert_result(days: int, min_days: int) -> CertResult:
    """OK only with more than min_days days left."""
    if days > min_days:
        return CertResult(ok=True, days=days, problem=None)
    if days < 0:
        return CertResult(ok=False, days=days, problem="certificate expired")
    return CertResult(ok=False, days=days, problem=f"certificate expires in {days} days")


# --------------------------------------------------------------------------- state and events


def load_state(path: str) -> Optional[dict]:
    """Previous run's state, or None if there is none (first run or cache miss) or it is unreadable."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        print("warning: previous state unreadable, treating this run as the first", file=sys.stderr)
        return None
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION or not isinstance(data.get("checks"), dict):
        print("warning: previous state has an unknown format, treating this run as the first", file=sys.stderr)
        return None
    return data


def save_state(path: str, state: dict) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temp, path)


@dataclass
class Check:
    key: str           # "http <url>" or "cert <host>"
    name: str          # public label used in messages
    ok: Optional[bool]  # None = unknown this run (keep the previous state, no message)
    detail: str        # problem, or a short success note


def compute_events(previous: Optional[dict], checks: list[Check]) -> tuple[dict, list[tuple[str, str]]]:
    """Compare this run with the previous state.

    Returns the new check states (key -> "ok" | "fail") and the events as (key, message) pairs.
    Rules: ok -> fail and fail -> ok are events; a check without a previous value is an event only
    if it fails; a previously failing check that is no longer configured is an event (so a test
    URL added through workflow_dispatch ends with a message); unknown results keep the old value.
    """
    old: dict = dict(previous["checks"]) if previous else {}
    new: dict = {}
    events: list[tuple[str, str]] = []
    for check in checks:
        before = old.get(check.key)
        if check.ok is None:
            if before is not None:
                new[check.key] = before
            continue
        now = "ok" if check.ok else "fail"
        new[check.key] = now
        if now == before:
            continue
        is_cert = check.key.startswith("cert ")
        if now == "fail":
            prefix = ":warning: CERT" if is_cert else ":red_circle: DOWN"
            events.append((check.key, f"{prefix} {check.name}: {check.detail}"))
        elif before == "fail":
            prefix = ":large_green_circle: CERT OK" if is_cert else ":large_green_circle: RECOVERED"
            events.append((check.key, f"{prefix} {check.name}: {check.detail}"))
    configured = {check.key for check in checks}
    for key, before in old.items():
        if key not in configured and before == "fail":
            name = key.split(" ", 1)[1] if " " in key else key
            if key.startswith("http "):
                name = label(name)
            events.append((key, f":white_circle: REMOVED {name}: no longer checked (was failing)"))
    return new, events


def keepalive_event(previous: Optional[dict], head_sha: Optional[str], head_time: Optional[int],
                    now: float) -> tuple[Optional[dict], Optional[str], Optional[int]]:
    """Reminder before GitHub disables the schedule (60 days without repository activity).

    Returns (new keepalive state, message or None, age in days or None).
    """
    if not head_sha or head_time is None:
        return (previous or {}).get("keepalive"), None, None
    age = int((now - head_time) // 86400)
    reached = [days for days in KEEPALIVE_REMIND_DAYS if age >= days]
    old = (previous or {}).get("keepalive") or {}
    level = max(reached) if reached else 0
    sent = old.get("level", 0) if old.get("sha") == head_sha else 0
    state = {"sha": head_sha, "level": max(level, sent)}
    if not reached or level <= sent:
        return state, None, age
    disable_on = dt.datetime.fromtimestamp(head_time + DISABLE_AFTER_DAYS * 86400, tz=dt.timezone.utc).date()
    message = (
        f":hourglass: KEEPALIVE homelab-uptime: the last commit on the default branch is {age} days old. "
        f"GitHub disables this scheduled check after {DISABLE_AFTER_DAYS} days without repository "
        f"activity (around {disable_on.isoformat()}). Push any commit to the default branch to keep it "
        "running; if it is already disabled, enable it again in the repository's Actions tab."
    )
    return state, message, age


# --------------------------------------------------------------------------- notifications


def slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_message(lines: list[str], run_url: Optional[str]) -> dict:
    text = "\n".join(slack_escape(line) for line in lines)
    if run_url:
        text += f"\n<{run_url}|details>"
    return {"text": text, "unfurl_links": False, "unfurl_media": False}


def post_slack(webhook: str, payload: dict, timeout: float = 15.0) -> bool:
    """POST the message; never prints the webhook URL. Returns True on HTTP 200."""
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(webhook, data=data, method="POST",
                                      headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        with opener.open(request, timeout=timeout) as response:
            response.read(1024)
            if response.status == 200:
                return True
            print(f"warning: Slack answered HTTP {response.status}", file=sys.stderr)
    except urllib.error.HTTPError as exc:
        print(f"warning: Slack answered HTTP {exc.code}", file=sys.stderr)
        exc.close()
    except Exception as exc:  # noqa: BLE001
        print(f"warning: Slack not reachable ({classify_error(exc)})", file=sys.stderr)
    return False


def annotate_warning(message: str) -> None:
    """GitHub Actions warning annotation (plain stderr line outside Actions)."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::warning::{message}")
    else:
        print(f"warning: {message}", file=sys.stderr)


# --------------------------------------------------------------------------- main


@dataclass
class TargetReport:
    url: str
    http: HttpResult
    cert: Optional[CertResult]

    @property
    def ok(self) -> bool:
        return self.http.ok and (self.cert is None or self.cert.ok is not False)

    def detail(self) -> str:
        if self.http.ok:
            detail = f"HTTP 200 in {self.http.elapsed:.2f} s"
        else:
            detail = self.http.problem or "failed"
        if self.cert is not None:
            if self.cert.days is not None:
                detail += f"; certificate {self.cert.days} days left"
            elif self.cert.problem:
                detail += f"; {self.cert.problem}"
        return detail

    def line(self) -> str:
        return f"{'OK  ' if self.ok else 'FAIL'}  {label(self.url)}  {self.detail()}"


def run_checks(targets: list[str], timeout: float, min_days: int, now: float,
               http_fn: Callable[[str, float], HttpResult] = check_http,
               cert_fn: Callable[..., CertResult] = check_cert) -> list[TargetReport]:
    https_hosts = sorted({host_of(url) for url in targets if url.startswith("https://")})
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        http_futures = {url: pool.submit(http_fn, url, timeout) for url in targets}
        cert_futures = {host: pool.submit(cert_fn, host, timeout, min_days, now) for host in https_hosts}
        certs = {host: future.result() for host, future in cert_futures.items()}
        return [TargetReport(url=url, http=http_futures[url].result(),
                             cert=certs.get(host_of(url)) if url.startswith("https://") else None)
                for url in targets]


def to_checks(reports: list[TargetReport]) -> list[Check]:
    checks: list[Check] = []
    seen_hosts: set[str] = set()
    for report in reports:
        http = report.http
        checks.append(Check(key=f"http {report.url}", name=label(report.url), ok=http.ok,
                            detail=(f"HTTP {http.status}" if http.ok else (http.problem or "failed"))))
        host = host_of(report.url)
        if report.cert is not None and host not in seen_hosts:
            seen_hosts.add(host)
            cert = report.cert
            detail = cert.problem if cert.ok is not True else f"{cert.days} days left"
            checks.append(Check(key=f"cert {host}", name=host, ok=cert.ok, detail=detail or ""))
    return checks


def write_summary(path: str, reports: list[TargetReport], notes: list[str]) -> None:
    rows = ["## Uptime check", "", "| Result | Target | Detail |", "| --- | --- | --- |"]
    for report in reports:
        rows.append(f"| {'OK' if report.ok else 'FAIL'} | `{label(report.url)}` | {report.detail()} |")
    if notes:
        rows.append("")
        rows.extend(f"- {note}" for note in notes)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(rows) + "\n")


def run_url_from_env() -> Optional[str]:
    server, repo, run_id = (os.environ.get(name) for name in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"))
    if server and repo and run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return None


def parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--targets", default="targets.txt", help="file with one URL per line")
    parser.add_argument("--state", default="state/state.json", help="state file (read and rewritten)")
    parser.add_argument("--extra-url", default="", help="one more URL for this run only (testing)")
    parser.add_argument("--timeout", type=float, default=15.0, help="seconds per request (default 15)")
    parser.add_argument("--cert-min-days", type=int, default=14, help="fail at or below this many days (default 14)")
    parser.add_argument("--head-sha", default="", help="commit of the default branch (keepalive reminder)")
    parser.add_argument("--head-time", type=int, default=None, help="its commit time, Unix seconds")
    parser.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY", ""), help="Markdown summary file")
    parser.add_argument("--no-notify", action="store_true", help="never post to Slack (local runs)")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None,
         http_fn: Callable[[str, float], HttpResult] = check_http,
         cert_fn: Callable[..., CertResult] = check_cert,
         post_fn: Callable[[str, dict], bool] = post_slack,
         now: Optional[float] = None) -> int:
    args = parse_args(argv)
    now = time.time() if now is None else now
    try:
        targets = load_targets(args.targets)
        if args.extra_url.strip():
            extra = validate_url(args.extra_url)
            if extra not in targets:
                targets.append(extra)
    except (ConfigError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    previous = load_state(args.state)
    reports = run_checks(targets, args.timeout, args.cert_min_days, now, http_fn, cert_fn)
    for report in reports:
        print(report.line())

    new_checks, events = compute_events(previous, to_checks(reports))
    keepalive, keepalive_message, age = keepalive_event(previous, args.head_sha or None, args.head_time, now)
    lines = [message for _, message in events]
    if keepalive_message:
        lines.append(keepalive_message)

    notes: list[str] = []
    if previous is None:
        notes.append("No previous state (first run or cache miss): only failures are reported.")
    if age is not None and age >= KEEPALIVE_REMIND_DAYS[0]:
        annotate_warning(f"last commit on the default branch is {age} days old; GitHub disables the schedule at {DISABLE_AFTER_DAYS} days")
        notes.append(f"Keepalive: last commit is {age} days old (schedule disabled after {DISABLE_AFTER_DAYS} days without activity).")

    delivered = True
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if lines:
        print(f"{len(lines)} state change(s) to report:")
        for line in lines:
            print(f"  {line}")
        if args.no_notify:
            notes.append("Slack: not sent (--no-notify).")
        elif not webhook:
            annotate_warning("SLACK_WEBHOOK_URL is not set: state changes are reported only in this log, the job summary and the exit code")
            notes.append("Slack: not sent, secret SLACK_WEBHOOK_URL is not set.")
        elif not webhook.startswith(SLACK_PREFIX):
            annotate_warning("SLACK_WEBHOOK_URL does not look like a Slack incoming webhook; nothing sent")
            notes.append("Slack: not sent, the webhook secret has an unexpected format.")
            delivered = False
        else:
            delivered = post_fn(webhook, build_message(lines, run_url_from_env()))
            notes.append("Slack: sent." if delivered else "Slack: delivery failed; the changes are reported again next run.")
            if not delivered:
                annotate_warning("Slack delivery failed; the changes are kept pending for the next run")
    else:
        print("no state changes")

    if not delivered:
        # Keep the old value of every changed check (a check without an old value stays absent)
        # and the old keepalive level, so the next run sees the same changes again.
        old_checks = (previous or {}).get("checks", {})
        for key, _ in events:
            if key in old_checks:
                new_checks[key] = old_checks[key]
            else:
                new_checks.pop(key, None)
        keepalive = (previous or {}).get("keepalive")
    state = {"version": STATE_VERSION, "checks": new_checks}
    if keepalive:
        state["keepalive"] = keepalive
    save_state(args.state, state)

    if args.summary:
        write_summary(args.summary, reports, notes)
    failed = sum(1 for report in reports if not report.ok)
    print(f"{len(reports) - failed}/{len(reports)} targets OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
