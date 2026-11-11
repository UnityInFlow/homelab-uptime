# homelab-uptime

External uptime check for the homelab's public sites. It runs on GitHub's own runners, so it still
reports when the whole homelab, its Internet line or its in-cluster alerting is down (layer 2a of the
homelab alerting design, `UnityInFlow/homelab-gitops#227`).

Every 15 minutes `.github/workflows/uptime.yml` runs `uptime_check.py` (Python 3, standard library
only) against each URL in [`targets.txt`](targets.txt):

- HTTP `GET` must end with status **200** within the timeout (15 s). At most 3 redirects are followed,
  only to public names; the final status counts. A failed request is retried once after 5 s before the
  target counts as down, so a single dropped request does not send a message.
- For `https` targets the host's TLS certificate must be valid for **more than 14 days**. For the
  current targets this is the certificate Cloudflare's edge presents; the homelab's own certificates
  behind the tunnel are watched by the in-cluster alerts. A certificate that cannot be read while the
  site answers counts as a failure (`CERT <host>: certificate not readable`).

Output: one line per target in the log, a table in the job summary, and exit code 1 (failed run) if
any target fails.

## Slack messages

The workflow posts to Slack (channel `#homelab-alerts`) through an incoming webhook, **only when a
state changes**:

| Message | When |
| --- | --- |
| `DOWN <host/path>: <problem>` | a target that was up fails (status, timeout, DNS, TLS) |
| `RECOVERED <host/path>` | a target that was down answers 200 again |
| `CERT <host>: certificate expires in N days` | a certificate drops to 14 days or less (or cannot be read) |
| `CERT OK <host>: N days left` | the certificate was renewed |
| `REMOVED <host/path>: no longer checked (was failing)` | a failing target left the list (e.g. a test URL) |
| `KEEPALIVE ...` | see [Keepalive](#keepalive) |

All changes of one run go into one message. Messages contain only public host names and paths, the
problem and a link to the run; no addresses, response bodies or error texts.

The previous state is kept in the Actions cache (`actions/cache/restore` + `actions/cache/save`, key
`uptime-state-<run id>-<attempt>`, restored by the prefix `uptime-state-`, so each run gets the newest
state). Without a previous state (first run, or the cache entry was evicted after 7 days without runs)
only failures are sent. A message that cannot be delivered (Slack error, secret missing) stays in the
state and goes out with the next message, marked `(detected <time>)`, so an outage that ended before
Slack was reachable is still reported; at most 20 are kept (older ones are counted as dropped).

Only runs on the default branch notify Slack and save the state (caches are per branch). A manual run
on another branch only checks and shows the result in its log and summary.

## Secrets

| Secret | Purpose |
| --- | --- |
| `SLACK_WEBHOOK_URL` | Repository secret: the Slack incoming webhook of this repository (its own webhook, separate from Alertmanager's, D-315). |

The webhook URL is handed to the script through the environment only, never as an argument, and is
never printed. Without the secret the run still fails on a down target, shows everything in the job
summary and logs a warning; messages stay pending until the secret exists.

## Test a failure (workflow_dispatch)

1. Actions -> `uptime` -> **Run workflow** on the default branch, `extra_url` = a public URL that does
   not answer 200, for example `https://hello.unityinflow.com/not-there` (404). Expected: the run
   fails and Slack gets one `DOWN hello.unityinflow.com/not-there: HTTP 404` message.
2. The next run without `extra_url` (scheduled, or **Run workflow** with the field empty) succeeds
   and Slack gets one `REMOVED hello.unityinflow.com/not-there` message.

`extra_url` accepts only `http`/`https` URLs of public ASCII DNS names on the default ports (no IP
addresses, no `*.home.*` names, no credentials); a name that resolves to a non-public address fails
the check without a request. The script reads the input from the event payload, not from the step's
environment (which the runner prints), and does not repeat a rejected value in the log.

## Run locally

```sh
python3 -m unittest discover -s tests -v                      # tests, no Internet needed
python3 uptime_check.py --no-notify --state /tmp/uptime.json  # real check of targets.txt, no Slack
python3 uptime_check.py --no-notify --state /tmp/uptime.json --extra-url https://hello.unityinflow.com/not-there
```

## Keepalive

GitHub: "In a public repository, scheduled workflows are automatically disabled when no repository
activity has occurred in 60 days" ([docs](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)).
GitHub does not document that re-enabling an enabled workflow through the API
(`PUT /repos/{owner}/{repo}/actions/workflows/{id}/enable`) resets that timer, so this repository
does not rely on it, and it makes no automatic commits. Instead every run compares the time of the
last commit on the default branch with the current time; at **50** and again at **57** days it sends a
`KEEPALIVE` message (and logs a warning from day 50 on). Any commit to the default branch (for example
a Renovate update or a README change) resets the count. If the schedule was disabled anyway: Actions
-> `uptime` -> **Enable workflow** (or `gh workflow enable uptime.yml`).

## Limits

- GitHub starts scheduled runs late, often 5-20 minutes and most at the start of the hour, and may
  drop runs under high load: a short outage can go unnoticed, and the alert can come about half an
  hour after the start of an outage.
- GitHub-hosted runners use shared cloud IP addresses; if Cloudflare's bot protection ever challenges them, a target shows
  `HTTP 403` although the site works for people.
- A failed run also triggers GitHub's own e-mail for failed scheduled runs (Settings -> Notifications
  -> Actions) at every run while a target is down.
- When GitHub Actions itself is down, nothing is checked; the separate healthchecks.io dead-man check
  (layer 2b) does not depend on GitHub.

## Changing the targets

Only names that are internet-facing through the Cloudflare Tunnel (the routes marked "public" in
`homelab-gitops` `docs/routes/`), never internal names, IP addresses or admin paths. `uptime_check.py`
refuses IP addresses, numeric, non-ASCII and internal names, names resolving to non-public
addresses and redirects to such names; the `test` workflow checks `targets.txt` on every pull
request. These checks guard against mistakes, not against an attacker: only people with write access
can change the targets or start a run, and the GitHub-hosted runner has no access to the homelab's
networks (a name that changes its DNS answer between the check and the request is not caught).

## License

[MIT](LICENSE)
