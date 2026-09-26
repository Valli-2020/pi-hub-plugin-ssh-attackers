#!/usr/bin/env python3
"""ssh-watch — tiny read-only collector for failed sshd connections.

Reads the sshd journal, groups connection attempts per source IP and
serves the most recent offenders as JSON on a single private address:

    GET /attackers?limit=5

Python stdlib only.  Needs read access to the journal (group
``systemd-journal``), nothing else.

Configure the bind address through the environment, never in the file:

    SSH_WATCH_BIND=100.100.100.1 SSH_WATCH_PORT=9101

The default is loopback: reach it through an SSH tunnel or bind it to a
management interface.  A public address would publish your attackers' IPs and
your usernames to anyone who asks.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BIND_HOST = os.environ.get("SSH_WATCH_BIND", "127.0.0.1").strip()
BIND_PORT = int(os.environ.get("SSH_WATCH_PORT", "9101"))
WINDOW_HOURS = int(os.environ.get("SSH_WATCH_WINDOW_HOURS", "24"))
CACHE_SECONDS = 15
MAX_LIMIT = 50
MAX_USERS = 3
JOURNAL_TIMEOUT = 20

LINE_RE = re.compile(
    r"^(?P<ts>\S+) \S+ sshd(?:-session)?\[(?P<pid>\d+)\]: (?P<msg>.*)$"
)
# One attempt = one sshd child (pid); several log lines of the same pid
# (Invalid user + Connection closed ...) must not be counted repeatedly.
FAIL_RES = (
    re.compile(r"^Invalid user (?P<user>.+?) from (?P<ip>\S+) port \d+"),
    re.compile(r"^Failed \S+ for (?:invalid user )?(?P<user>.+?) from "
               r"(?P<ip>\S+) port \d+"),
    re.compile(r"^(?:Connection (?:closed|reset)|Disconnected|Timeout before "
               r"authentication) (?:by|from) (?:invalid|authenticating) user "
               r"(?P<user>.+?) (?P<ip>\S+) port \d+"),
    re.compile(r"^Connection (?:closed|reset) by (?P<ip>[0-9A-Fa-f:.]+) "
               r"port \d+"),
    re.compile(r"^Unable to negotiate with (?P<ip>\S+) port \d+"),
    re.compile(r"^banner exchange: Connection from (?P<ip>\S+) port \d+"),
)
ACCEPTED_RE = re.compile(r"^Accepted ")


def _parse_ts(raw: str) -> float:
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S%z").timestamp()


def _public_ip(raw: str) -> str | None:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def parse(lines: list[str]) -> dict[str, dict]:
    """Return ``{ip: {"last": epoch, "pids": set, "users": [...]}}``."""
    pids: dict[str, dict] = {}
    accepted: set[str] = set()
    for line in lines:
        m = LINE_RE.match(line)
        if not m:
            continue
        pid, msg = m["pid"], m["msg"]
        if ACCEPTED_RE.match(msg):
            accepted.add(pid)
            continue
        for rx in FAIL_RES:
            f = rx.match(msg)
            if not f:
                continue
            ip = _public_ip(f["ip"])
            if ip is None:
                break
            try:
                ts = _parse_ts(m["ts"])
            except ValueError:
                break
            entry = pids.setdefault(pid, {"ip": ip, "ts": ts, "users": []})
            entry["ts"] = max(entry["ts"], ts)
            user = f.groupdict().get("user")
            if user and user not in entry["users"]:
                entry["users"].append(user)
            break

    per_ip: dict[str, dict] = {}
    for pid, e in sorted(pids.items(), key=lambda kv: kv[1]["ts"]):
        if pid in accepted:
            continue
        row = per_ip.setdefault(e["ip"], {"last": 0.0, "attempts": 0, "users": []})
        row["attempts"] += 1
        row["last"] = max(row["last"], e["ts"])
        for user in e["users"]:
            if user in row["users"]:
                row["users"].remove(user)
            row["users"].append(user)
    return per_ip


def read_journal() -> list[str]:
    out = subprocess.run(
        ["journalctl", "-u", "ssh", "-u", "sshd",
         "--since", f"{WINDOW_HOURS} hours ago",
         "-o", "short-iso", "--no-pager", "-q"],
        capture_output=True, text=True, timeout=JOURNAL_TIMEOUT, check=True,
    )
    return out.stdout.splitlines()


_cache_lock = threading.Lock()
_cache: dict = {"at": 0.0, "data": None}


def snapshot() -> dict:
    with _cache_lock:
        if _cache["data"] is not None and time.time() - _cache["at"] < CACHE_SECONDS:
            return _cache["data"]
        per_ip = parse(read_journal())
        ranked = sorted(per_ip.items(), key=lambda kv: kv[1]["last"], reverse=True)
        data = {
            "window_hours": WINDOW_HOURS,
            "total_attempts": sum(r["attempts"] for _, r in ranked),
            "unique_ips": len(ranked),
            "attackers": [
                {
                    "ip": ip,
                    "last_seen": datetime.fromtimestamp(
                        r["last"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "attempts": r["attempts"],
                    "users": r["users"][-MAX_USERS:][::-1],
                }
                for ip, r in ranked[:MAX_LIMIT]
            ],
        }
        _cache["at"], _cache["data"] = time.time(), data
        return data


class Handler(BaseHTTPRequestHandler):
    server_version = "ssh-watch"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        url = urlparse(self.path)
        if url.path != "/attackers":
            self._send(404, {"error": "not found"})
            return
        try:
            limit = int(parse_qs(url.query).get("limit", ["5"])[0])
        except ValueError:
            limit = 5
        limit = max(1, min(limit, MAX_LIMIT))
        try:
            data = dict(snapshot())
        except (subprocess.SubprocessError, OSError) as e:
            print(f"journal read failed: {e}", file=sys.stderr)
            self._send(503, {"error": "journal unavailable"})
            return
        data["attackers"] = data["attackers"][:limit]
        self._send(200, data)

    def log_message(self, fmt: str, *args) -> None:
        pass


def main() -> None:
    try:
        addr = ipaddress.ip_address(BIND_HOST)
    except ValueError:
        print(f"SSH_WATCH_BIND is not an IP address: {BIND_HOST}", file=sys.stderr)
        raise SystemExit(2)
    if not addr.is_private and not addr.is_loopback:
        print(f"refusing to publish attacker data on the public address {addr}",
              file=sys.stderr)
        raise SystemExit(2)
    print(f"ssh-watch on {BIND_HOST}:{BIND_PORT} "
          f"(window {WINDOW_HOURS} h, cache {CACHE_SECONDS} s)", file=sys.stderr)
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
