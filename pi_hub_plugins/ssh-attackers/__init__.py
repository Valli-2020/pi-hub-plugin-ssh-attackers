"""SSH attackers — live failed-login monitor for a remote sshd host.

Polls the small ``ssh-watch`` collector (a stdlib HTTP service next to sshd,
Tailnet-only) and enriches every source IP with country / city / ISP / ASN
(ipwho.is) and reverse DNS.

Two surfaces:

* a **status bar in the topbar** (``header.pill``) that appears while an
  attack is running and counts down a cooldown, so a burst of failed logins
  is visible without opening the tab;
* a **tab** with the ranked attacker table.

Moving parts:

* a **background refresher thread** rebuilds a snapshot and swaps it under a
  lock, so providers never do network I/O (the core gives them a 3 s budget)
  and several open browser tabs cannot multiply the fan-out;
* a **per-IP enrichment cache** (``geo_ttl`` seconds, bounded) so a persistent
  attacker costs one lookup per day, not one per poll;
* **adaptive polling**: ``active_poll_interval`` while an attack is inside its
  cooldown, ``poll_interval`` otherwise.

Detection latency is bounded by the collector, not by this plugin: the
collector answers from a short-lived cache, so the bar lights up within a few
seconds of a real attempt.  ``cooldown_seconds`` then keeps it visible so a
human actually sees it.

Every table row carries exactly the same keys, in the same order, and every
unknown value is ``DASH`` — never ``None``, which a table node would print
literally.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timezone
from typing import Any

from pi_hub.plugins.base import Contribution, Plugin, PluginContext, RouteDef

log = logging.getLogger(__name__)

DASH = "–"

GEO_URL = "https://ipwho.is/{ip}?fields=success,country,region,city,connection"
RDNS_TIMEOUT_S = 3.0
GEO_TIMEOUT_S = 6
GEO_FAIL_TTL_S = 600
GEO_CACHE_MAX = 200
MAX_COLLECTOR_BYTES = 1 << 20
MAX_GEO_BYTES = 1 << 16

ROW_KEYS = ("ip", "last_seen", "attempts", "country", "city", "isp", "asn",
            "rdns", "users")

#: The collector URL is deliberately empty: every deployment sets it in
#: Settings → Plugins → Configure.  Shipping a real address in a public
#: repository would leak the operator's tailnet.
DEFAULT_CONFIG: dict[str, Any] = {
    "collector_url": "",
    "poll_interval": 60,
    "active_poll_interval": 10,
    "cooldown_seconds": 60,
    "min_attempts": 1,
    "limit": 5,
    "geo_ttl": 86400,
    "timeout": 8,
}

MIN_POLL, MAX_POLL = 10, 3600
MIN_ACTIVE_POLL, MAX_ACTIVE_POLL = 5, 300
MIN_COOLDOWN, MAX_COOLDOWN = 15, 600
MIN_ATTEMPTS, MAX_ATTEMPTS = 1, 1000
MIN_LIMIT, MAX_LIMIT = 1, 20
MIN_TIMEOUT, MAX_TIMEOUT = 1, 60

#: The bar counts down to zero and disappears; this is its client refresh.
PILL_POLL_S = 5
TAB_POLL_S = 30
#: A failed read older than this many poll intervals is reported as offline
#: instead of silently pretending there is nothing happening.
STALE_FACTOR = 3

SHIELD_ICON = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="1.8" stroke-linecap="round" '
    'stroke-linejoin="round">'
    '<path d="M12 3l8 3v6c0 4.5-3.2 8.2-8 9-4.8-.8-8-4.5-8-9V6z"/>'
    '<path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/></svg>'
)

#: Scoped to ``.plg-ssh-attackers`` by the core, so it can only restyle this
#: plugin's own nodes.  The bar itself is the node stack, because the slot
#: wrapper around it is ``display:contents`` and paints nothing.
BAR_CSS = """
.ph-stack[data-dir="row"] { display:inline-flex; align-items:center; gap:8px;
  height:26px; padding:0 10px; border-radius:99px;
  border:1px solid color-mix(in oklab, var(--bad) 45%, var(--border));
  background:color-mix(in oklab, var(--bad) 12%, var(--surface)); }
.ph-badge { font-variant-numeric:tabular-nums; }
.usage { min-width:0; gap:6px; }
.usage .val { min-width:44px; font-size:11.5px; }
.usage .bar { width:56px; flex:none; }
.bar i[data-warm], .bar i[data-hot], .bar i { background:var(--bad); }
"""

#: ``http://host[:port]`` only — no path, no userinfo, no CR/LF.
_BASE_URL_RE = re.compile(r"http://[A-Za-z0-9.\-]+(:[0-9]{1,5})?")
_IP_RE = re.compile(r"[0-9A-Fa-f:.]{2,45}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect so a hijacked endpoint cannot bounce us around."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def valid_base_url(url: str) -> bool:
    """True when *url* is a bare ``http://host[:port]`` with no CR/LF."""
    if not url or "\r" in url or "\n" in url:
        return False
    return _BASE_URL_RE.fullmatch(url) is not None


def _clamp(value: Any, low: int, high: int, fallback: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return fallback


def _ago(epoch: float, now: float) -> str:
    secs = max(0, int(now - epoch))
    if secs < 60:
        return f"{secs} s ago"
    if secs < 3600:
        return f"{secs // 60} min ago"
    if secs < 86400:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} d ago"


def _get_json(url: str, timeout: int, max_bytes: int) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with _OPENER.open(req, timeout=timeout) as resp:
        raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("response too large")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("unexpected payload")
    return data


def _text(value: Any) -> str:
    """Printable, single-line, length-capped string; DASH when empty."""
    if value is None:
        return DASH
    out = "".join(c if c.isprintable() else " " for c in str(value)).strip()
    return out[:60] or DASH


def _plural(count: int, one: str, many: str | None = None) -> str:
    """German plural: 1 IP, 2 IPs, 1 Versuch, 2 Versuche."""
    return one if count == 1 else (many or one + "s")


# ── Attack state (pure functions — no clock, no network, no lock) ──────────


def recent_rows(snapshot: dict[str, Any], now: float, cooldown_s: int) -> list[dict[str, Any]]:
    """Rows whose last attempt is inside the cooldown, newest first.

    A timestamp from the future (collector and dashboard clocks drifting apart)
    counts as age zero instead of dropping the row.
    """
    rows = [r for r in snapshot.get("rows") or [] if r.get("_last")]
    rows.sort(key=lambda r: r["_last"], reverse=True)
    return [r for r in rows if _age(now, r) <= cooldown_s]


def _age(now: float, row: dict[str, Any]) -> float:
    return max(0.0, now - float(row["_last"]))


def alert_summary(snapshot: dict[str, Any], now: float,
                  cfg: dict[str, Any]) -> dict[str, Any] | None:
    """Describe the running attack, or ``None`` when there is none.

    ``None`` is what hides the bar: a provider returning nothing renders no
    node at all, so the topbar goes back to its normal state.
    """
    rows = recent_rows(snapshot, now, cfg["cooldown_seconds"])
    if not rows:
        return None
    attempts = sum(int(r.get("attempts") or 0) for r in rows)
    if attempts < cfg["min_attempts"]:
        return None
    age = _age(now, rows[0])
    # Both numbers are cut from the same float so the bar never shows
    # "vor 4 s" next to "noch 55 s" of a 60 s cooldown.
    age_s = int(age)
    left_s = max(0, cfg["cooldown_seconds"] - age_s)
    return {
        "ips": len(rows),
        "attempts": attempts,
        "newest": rows[0],
        "age": age_s,
        "left": left_s,
        "pct": int(round(left_s / cfg["cooldown_seconds"] * 100)),
    }


def monitor_state(snapshot: dict[str, Any], now: float, cfg: dict[str, Any]) -> str:
    """``active`` | ``idle`` | ``offline``; ``starting`` before the first read."""
    if not snapshot.get("at"):
        return "starting"
    if alert_summary(snapshot, now, cfg):
        return "active"
    stale = STALE_FACTOR * cfg["poll_interval"]
    if snapshot.get("error") and now - snapshot["at"] > stale:
        return "offline"
    return "idle"


def pill_node(summary: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """Topbar bar: what is happening, for how long, and how much cooldown is left."""
    newest = summary["newest"]
    title = (
        f'{summary["ips"]} source IP(s), {summary["attempts"]} failed attempts '
        f'within {cfg["cooldown_seconds"]} s\n'
        f'Newest: {newest["ip"]} ({newest["country"]}, {newest["city"]}) '
        f'as {newest["users"]}'
    )
    return {
        "type": "stack", "dir": "row",
        "children": [
            {"type": "status", "state": "bad", "text": "SSH-Attack"},
            {"type": "badge", "tone": "bad", "title": title,
             "text": (f'{summary["ips"]} {_plural(summary["ips"], "IP")} · '
                      f'{summary["attempts"]} {_plural(summary["attempts"], "Versuch", "Versuche")} '
                      f'· vor {summary["age"]} s')},
            {"type": "progress", "pct": summary["pct"],
             "text": f'noch {summary["left"]} s'},
        ],
    }


def offline_node(snapshot: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """Say the monitor is blind instead of implying the host is quiet."""
    return {
        "type": "status", "state": "unknown", "text": "SSH-Monitor offline",
        "title": (f'Last successful read: {_ago(snapshot["at"], time.time())} — '
                  f'collector error: {snapshot.get("error") or "unknown"}'),
    }


def tab_node(snapshot: dict[str, Any], now: float, cfg: dict[str, Any]) -> dict[str, Any]:
    """Ranked attacker table plus the numbers that give it context."""
    alert = alert_summary(snapshot, now, cfg)
    window = snapshot.get("window") or 24
    rows = [{
        "ip": r["ip"],
        "last_seen": _ago(r["_last"], now) if r["_last"] else DASH,
        "attempts": r.get("attempts", 0),
        "country": r["country"],
        "city": r["city"],
        "isp": r["isp"],
        "asn": r["asn"],
        "rdns": r["rdns"],
        "users": r["users"],
        "_id": r["ip"],
    } for r in snapshot.get("rows") or []]
    summary = [
        ["Fenster", f"{window} h"],
        ["Versuche", _text(snapshot.get("attempts"))],
        ["Eindeutige IPs", _text(snapshot.get("unique"))],
        ["Gerade aktiv", (f'{alert["ips"]} IPs · vor {alert["age"]} s' if alert else "keine")],
        ["Cooldown", f'{cfg["cooldown_seconds"]} s (Poll {PILL_POLL_S} s)'],
        ["Quelle", f'collector {_ago(snapshot["at"], now) if snapshot.get("at") else DASH}'],
    ]
    if snapshot.get("error"):
        summary.append(["Fehler", _text(snapshot["error"])])
    return {
        "type": "stack", "dir": "col",
        "children": [
            {"type": "kv", "rows": summary},
            {
                "type": "table",
                "columns": [
                    {"key": "ip", "label": "IP", "mono": True},
                    {"key": "last_seen", "label": "Zuletzt gesehen"},
                    {"key": "attempts", "label": "Versuche", "align": "right"},
                    {"key": "country", "label": "Land"},
                    {"key": "city", "label": "Stadt"},
                    {"key": "isp", "label": "ISP"},
                    {"key": "asn", "label": "ASN"},
                    {"key": "rdns", "label": "rDNS"},
                    {"key": "users", "label": "Benutzer"},
                ],
                "rows": rows,
            },
        ],
    }


class SshAttackersPlugin(Plugin):
    name = "ssh-attackers"
    version = "1.1.0"
    description = (
        "Live failed-sshd-login monitor: a topbar alert with a cooldown while "
        "an attack runs, plus a ranked attacker table with country, ISP, ASN "
        "and reverse DNS"
    )
    min_core_version = "8.0.0"
    plugin_api_version = 2
    capabilities: list[str] = ["ui.header", "ui.style", "ui.tab"]

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def load(self, ctx: PluginContext) -> None:
        self.ctx = ctx
        self._lock = threading.Lock()
        self._snapshot: dict[str, Any] = {}
        self._geo: dict[str, tuple[float, dict[str, str]]] = {}
        self._stop = threading.Event()
        self._dns = ThreadPoolExecutor(max_workers=2,
                                       thread_name_prefix="ssh-attackers-dns")

        cfg = self.ctx.get_config()
        changed = False
        for key, value in DEFAULT_CONFIG.items():
            if key not in cfg:
                cfg[key] = value
                changed = True
        if changed:
            self.ctx.save_config()

        self._thread = threading.Thread(
            target=self._refresh_loop, name="ssh-attackers-refresh",
            daemon=True)
        self._thread.start()

    def unload(self) -> None:
        self._stop.set()
        thread = getattr(self, "_thread", None)
        if thread is not None:
            thread.join(timeout=3.0)
        self._dns.shutdown(wait=False)

    # ── Descriptors ────────────────────────────────────────────────────────

    def get_routes(self) -> list[RouteDef]:
        return [RouteDef("GET", "/status", self.status_handler, caps=["admin"])]

    def get_contributions(self) -> list[Contribution]:
        return [
            Contribution("header.pill", "alert", self.provider_pill,
                         poll=PILL_POLL_S, caps=["admin"]),
            Contribution("tab", "attackers", self.provider_tab,
                         poll=TAB_POLL_S, label="SSH attackers",
                         icon_svg=SHIELD_ICON, caps=["admin"]),
            Contribution("style", "bar", static={"css": BAR_CSS}),
        ]

    def get_config_schema(self) -> list[dict[str, Any]]:
        return [
            {"name": "collector_url", "label": "Collector URL",
             "type": "text", "required": True,
             "placeholder": "http://192.0.2.10:9101",
             "help": "Base URL of the ssh-watch collector, no path."},
            {"name": "cooldown_seconds", "label": "Cooldown (s)",
             "type": "number", "default": DEFAULT_CONFIG["cooldown_seconds"],
             "min": MIN_COOLDOWN, "max": MAX_COOLDOWN,
             "help": "How long the topbar bar stays visible after the last attempt."},
            {"name": "min_attempts", "label": "Min. Versuche",
             "type": "number", "default": DEFAULT_CONFIG["min_attempts"],
             "min": MIN_ATTEMPTS, "max": MAX_ATTEMPTS,
             "help": "Failed attempts inside the window needed to raise the alarm."},
            {"name": "poll_interval", "label": "Poll interval (s)",
             "type": "number", "default": DEFAULT_CONFIG["poll_interval"],
             "min": MIN_POLL, "max": MAX_POLL},
            {"name": "active_poll_interval", "label": "Poll during attack (s)",
             "type": "number", "default": DEFAULT_CONFIG["active_poll_interval"],
             "min": MIN_ACTIVE_POLL, "max": MAX_ACTIVE_POLL},
            {"name": "limit", "label": "Rows in the table",
             "type": "number", "default": DEFAULT_CONFIG["limit"],
             "min": MIN_LIMIT, "max": MAX_LIMIT},
            {"name": "geo_ttl", "label": "Geo cache TTL (s)",
             "type": "number", "default": DEFAULT_CONFIG["geo_ttl"],
             "min": 60, "max": 30 * 86400},
            {"name": "timeout", "label": "HTTP timeout (s)",
             "type": "number", "default": DEFAULT_CONFIG["timeout"],
             "min": MIN_TIMEOUT, "max": MAX_TIMEOUT},
        ]

    # ── Config ─────────────────────────────────────────────────────────────

    def _config_snapshot(self) -> dict[str, Any]:
        with self._lock:
            cfg = dict(self.ctx.get_config())
        defaults = DEFAULT_CONFIG
        return {
            "collector_url": str(cfg.get("collector_url", "")).rstrip("/"),
            "poll_interval": _clamp(cfg.get("poll_interval"), MIN_POLL,
                                    MAX_POLL, defaults["poll_interval"]),
            "active_poll_interval": _clamp(cfg.get("active_poll_interval"),
                                           MIN_ACTIVE_POLL, MAX_ACTIVE_POLL,
                                           defaults["active_poll_interval"]),
            "cooldown_seconds": _clamp(cfg.get("cooldown_seconds"), MIN_COOLDOWN,
                                       MAX_COOLDOWN, defaults["cooldown_seconds"]),
            "min_attempts": _clamp(cfg.get("min_attempts"), MIN_ATTEMPTS,
                                   MAX_ATTEMPTS, defaults["min_attempts"]),
            "limit": _clamp(cfg.get("limit"), MIN_LIMIT, MAX_LIMIT,
                            defaults["limit"]),
            "geo_ttl": _clamp(cfg.get("geo_ttl"), 60, 30 * 86400,
                              defaults["geo_ttl"]),
            "timeout": _clamp(cfg.get("timeout"), MIN_TIMEOUT, MAX_TIMEOUT,
                              defaults["timeout"]),
        }

    # ── Refresher ──────────────────────────────────────────────────────────

    def _refresh_loop(self) -> None:
        while not self._stop.is_set():
            delay = float(self._config_snapshot()["poll_interval"])
            try:
                delay = self._refresh_once()
            except Exception:               # a crashed refresher is worse
                log.exception("ssh-attackers: refresh cycle crashed")
            if self._stop.wait(delay):
                return

    def _refresh_once(self) -> float:
        cfg = self._config_snapshot()
        idle_delay = float(cfg["poll_interval"])
        if not valid_base_url(cfg["collector_url"]):
            self._store_error("invalid collector_url")
            return idle_delay
        url = f"{cfg['collector_url']}/attackers?limit={cfg['limit']}"
        try:
            data = _get_json(url, cfg["timeout"], MAX_COLLECTOR_BYTES)
        except (urllib.error.URLError, OSError, ValueError) as e:
            log.warning("ssh-attackers: collector request failed: %s", e)
            self._store_error("unreachable")
            return idle_delay

        rows: list[dict[str, Any]] = []
        for entry in (data.get("attackers") or [])[:cfg["limit"]]:
            if self._stop.is_set():
                return idle_delay
            row = self._build_row(entry, cfg)
            if row is not None:
                rows.append(row)
        with self._lock:
            self._snapshot = {
                "error": "",
                "at": time.time(),
                "attempts": _clamp(data.get("total_attempts"), 0, 1 << 40, 0),
                "unique": _clamp(data.get("unique_ips"), 0, 1 << 40, 0),
                "window": _clamp(data.get("window_hours"), 1, 24 * 30, 24),
                "rows": rows,
            }

        # A running attack gets a short poll so the bar tracks new sources;
        # once the cooldown has expired we fall back to the slow cadence.
        with self._lock:
            snap = dict(self._snapshot)
        if alert_summary(snap, time.time(), cfg):
            return float(cfg["active_poll_interval"])
        return idle_delay

    def _store_error(self, message: str) -> None:
        with self._lock:
            self._snapshot = {**self._snapshot, "error": message}

    # ── Row building / enrichment ──────────────────────────────────────────

    def _build_row(self, entry: Any, cfg: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(entry, dict):
            return None
        ip = str(entry.get("ip", ""))
        if not _IP_RE.fullmatch(ip):
            return None
        try:
            last = datetime.strptime(
                str(entry.get("last_seen", "")), "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            last = 0.0
        users = entry.get("users")
        info = self._lookup(ip, cfg)
        return {
            "ip": ip,
            "_last": last,
            "attempts": _clamp(entry.get("attempts"), 0, 1 << 40, 0),
            "country": info["country"],
            "city": info["city"],
            "isp": info["isp"],
            "asn": info["asn"],
            "rdns": info["rdns"],
            "users": ", ".join(_text(u) for u in users[:3])
            if isinstance(users, list) and users else DASH,
        }

    def _lookup(self, ip: str, cfg: dict[str, Any]) -> dict[str, str]:
        now = time.time()
        with self._lock:
            hit = self._geo.get(ip)
        if hit is not None and hit[0] > now:
            return hit[1]

        info = {"country": DASH, "city": DASH, "isp": DASH, "asn": DASH,
                "rdns": self._reverse_dns(ip)}
        ttl = GEO_FAIL_TTL_S
        try:
            geo = _get_json(GEO_URL.format(ip=ip), GEO_TIMEOUT_S, MAX_GEO_BYTES)
            if geo.get("success") is True:
                conn = geo.get("connection")
                conn = conn if isinstance(conn, dict) else {}
                asn = conn.get("asn")
                info.update(
                    country=_text(geo.get("country")),
                    city=_text(geo.get("city") or geo.get("region")),
                    isp=_text(conn.get("isp") or conn.get("org")),
                    asn=f"AS{asn}" if isinstance(asn, int) else DASH,
                )
                ttl = cfg["geo_ttl"]
        except (urllib.error.URLError, OSError, ValueError) as e:
            log.warning("ssh-attackers: geo lookup for %s failed: %s", ip, e)

        with self._lock:
            if len(self._geo) >= GEO_CACHE_MAX:
                oldest = min(self._geo, key=lambda k: self._geo[k][0])
                del self._geo[oldest]
            self._geo[ip] = (now + ttl, info)
        return info

    def _reverse_dns(self, ip: str) -> str:
        future = self._dns.submit(socket.gethostbyaddr, ip)
        try:
            return _text(future.result(timeout=RDNS_TIMEOUT_S)[0])
        except (socket.herror, socket.gaierror, OSError, FutureTimeout):
            return DASH

    # ── Providers (snapshot only — never network I/O) ──────────────────────

    def provider_pill(self, session: Any = None) -> dict[str, Any] | None:
        """Topbar bar while an attack runs; ``None`` renders nothing at all."""
        cfg = self._config_snapshot()
        now = time.time()
        with self._lock:
            snap = dict(self._snapshot)
        state = monitor_state(snap, now, cfg)
        if state == "starting":
            return None
        if state == "offline":
            return offline_node(snap, cfg)
        if state != "active":
            return None
        summary = alert_summary(snap, now, cfg)
        return pill_node(summary, cfg) if summary else None

    def provider_tab(self, session: Any = None) -> dict[str, Any]:
        cfg = self._config_snapshot()
        with self._lock:
            snap = dict(self._snapshot)
        return tab_node(snap, time.time(), cfg)

    # ── HTTP ───────────────────────────────────────────────────────────────

    def status_handler(self, **kw: Any) -> tuple[Any, int]:
        cfg = self._config_snapshot()
        now = time.time()
        with self._lock:
            snap = dict(self._snapshot)
        if not snap.get("at"):
            return {
                "collector": snap.get("error") or "starting…",
                "attackers": [],
            }, 200
        alert = alert_summary(snap, now, cfg)
        rows = [
            {"ip": r["ip"], "last_seen": _ago(r["_last"], now) if r["_last"] else DASH,
             **{k: r[k] for k in ROW_KEYS if k not in ("ip", "last_seen")}}
            for r in snap["rows"]
        ]
        return {
            "collector": snap.get("error") or "ok",
            "state": monitor_state(snap, now, cfg),
            "cooldown_left": alert["left"] if alert else 0,
            f"attempts_{snap['window']}h": snap["attempts"],
            f"unique_ips_{snap['window']}h": snap["unique"],
            "updated": _ago(snap["at"], now),
            "attackers": rows,
        }, 200
