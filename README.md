# pi-hub-plugin-ssh-attackers

A [Pi Hub](https://github.com/Valli-2020/pi-hub) plugin (**Plugin API v2**,
Pi Hub 8.0+) that turns "someone is hammering my sshd right now" into something
you actually see.

* **Topbar alert** — while an attack is running, a red bar appears in the Pi Hub
  header with the number of source IPs, the failed attempts, how long ago the
  newest attempt was, and a **cooldown countdown**. It disappears when the
  cooldown runs out, so a burst is never missed and never nags.
* **Attacker table** — the ranked sources with country, city, ISP, ASN, reverse
  DNS and the usernames they tried.
* **Honest about blindness** — if the collector cannot be reached for several
  poll intervals, the bar says *SSH-Monitor offline* instead of pretending the
  host is quiet.

Python standard library only, like Pi Hub itself.

## Screens

```
● Pi Hub     [ 6 up ]  [ SSH-Attack  2 IPs · 85 Versuche · vor 29 s  ▓▓▓▓░░░░░ noch 31 s ]
```

## Install

**From the Pi Hub plugin store (Settings → Plugins):** add this repository as a
source, install *ssh-attackers*, then **Enable** and approve the declared
capabilities (`ui.header`, `ui.style`, `ui.tab` — all UI-only).

**Manually:** copy `pi_hub_plugins/ssh-attackers/` into Pi Hub's
`pi_hub_plugins/` directory and add `"ssh-attackers"` to
`pi_hub_plugins/plugins.json` → `{"enabled": [...]}`.

Then open **Settings → Plugins → ssh-attackers → Configure** and set the
collector URL. Nothing else is required; the plugin ships with no address
hardcoded.

## The collector

The plugin does not read the journal itself. It talks to `ssh-watch`, a ~150
line read-only service that runs next to sshd and answers one question:
*who tried to log in, and when?*

`collector/ssh_watch.py` in this repository is that service. It reads the sshd
journal (needs membership in `systemd-journal`), groups the failed attempts per
source IP, and serves them as JSON on a private address:

```bash
# on the host that runs sshd
install -m 0755 collector/ssh_watch.py /opt/ssh-watch/ssh_watch.py
```

```ini
# /etc/systemd/system/ssh-watch.service
[Unit]
Description=ssh-watch - recent failed sshd connections as JSON
After=network-online.target
Wants=network-online.target

[Service]
User=sshwatch
Group=sshwatch
SupplementaryGroups=systemd-journal
Environment=SSH_WATCH_BIND=192.0.2.10
ExecStart=/usr/bin/python3 /opt/ssh-watch/ssh_watch.py
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
MemoryMax=64M

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now ssh-watch
curl 'http://192.0.2.10:9101/attackers?limit=5'
```

```json
{
  "window_hours": 24,
  "total_attempts": 2905,
  "unique_ips": 419,
  "attackers": [
    {"ip": "92.118.39.77", "last_seen": "2026-09-26T22:26:33Z",
     "attempts": 46, "users": ["root", "admin"]}
  ]
}
```

**Bind it to a private interface only** (Tailscale, a management VLAN, an
`ssh -L` tunnel). It is plain HTTP and unauthenticated by design: the journal
data is not worth a TLS stack, the network path is. One failed attempt equals
one sshd child process, so a burst of log lines from one connection is counted
once, and an `Accepted` line cancels the attempt.

## Configuration

Everything is set in **Settings → Plugins → ssh-attackers → Configure**. Changes
apply live: the plugin polls again right away.

| Field | Section | Type | Default | Meaning |
|---|---|---|---|---|
| `collector_url` | Collector | url | *(empty)* | Base URL of `ssh-watch`, no path — e.g. `http://192.0.2.10:9101` |
| `poll_interval` | Collector | number | `60` | Collector poll while quiet (s) |
| `active_poll_interval` | Collector | number | `10` | Collector poll while the alert is up (s) |
| `timeout` | Collector | number | `8` | HTTP timeout for the collector (s) |
| `limit` | Collector | number | `5` | Rows in the table (and the number of IPs enriched) |
| `cooldown_seconds` | Alert | number | `60` | How long the topbar bar stays visible after the last attempt |
| `min_attempts` | Alert | number | `1` | Failed attempts inside the window needed to raise the alarm |
| `geo_enabled` | Enrichment | checkbox | on | Look up country / ISP / ASN (sends each attacker IP to the service) |
| `geo_url` | Enrichment | url | ipwho.is | Lookup URL template containing `{ip}`; ipwho.is-style JSON |
| `geo_timeout` | Enrichment | number | `6` | Lookup timeout (s) |
| `geo_ttl` | Enrichment | number | `86400` | Lookup cache lifetime per IP (s) |
| `rdns_enabled` | Enrichment | checkbox | on | Resolve reverse DNS names |
| `rdns_timeout` | Enrichment | number | `3` | Reverse DNS timeout (s) |

Collector-side settings (listen address, window, cache) belong to `collector/ssh_watch.py`
on the monitored host and are not plugin settings.

Detection latency is the collector's, not the plugin's: `ssh-watch` answers from
a 15 s cache, so the bar lights up within a few seconds of a real attempt — the
cooldown then keeps it on screen long enough to be read.

## How it works

```
sshd journal ──▶ ssh-watch (VPS, :9101)  ──HTTP──▶  plugin refresher thread
                                                          │  snapshot under a lock
                                    ┌─────────────────────┴─────────────────────┐
                                    ▼                                           ▼
                        header.pill provider                          tab provider
                     (5 s poll, JSON nodes)                    (30 s poll, table node)
```

* Providers **never** do network I/O — the core gives them a 3 s budget and the
  refresher thread owns every request. Several open browser tabs therefore cost
  one poll, not one poll each.
* Geo lookups (ipwho.is) and reverse DNS are cached per IP for `geo_ttl`, so a
  persistent attacker costs one lookup a day.
* Nothing is sent to ipwho.is except the attacker's IP address, and only for IPs
  the collector already reported.
* The plugin is declarative: it emits JSON nodes, never HTML, so the core
  renders and escapes everything. Its CSS is sanitised and scoped to
  `.plg-ssh-attackers`.

## Tests

```bash
PIHUB_DIR=/path/to/pi-hub python3 -m unittest discover -s tests -v
```

22 tests, stdlib `unittest`. The integration tests run the plugin against a real
HTTP collector on `127.0.0.1` with geo and DNS stubbed — no network egress.

## Security notes

* The collector binds to a private address and serves plain HTTP; do not expose
  it to the internet.
* The plugin's capabilities are UI-only (`ui.header`, `ui.style`, `ui.tab`) — it
  asks for no system access and reads the collector over HTTP GET only.
* `collector_url` is validated as a bare `http://host[:port]` — no path, no
  userinfo, no CRLF — and redirects are refused, so a hijacked endpoint cannot
  bounce the plugin somewhere else.

## License

MIT
