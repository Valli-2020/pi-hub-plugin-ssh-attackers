"""Tests for the ssh-attackers plugin.

Run against a Pi Hub checkout:

    PIHUB_DIR=/home/pi/projects/pi-hub/pi-hub-dev python3 -m unittest discover -s tests -v

Stdlib only — Pi Hub has no pip, and neither should its plugins' tests.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import sys
import threading
import time
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PLUGIN_DIR = pathlib.Path(__file__).resolve().parents[1] / "pi_hub_plugins" / "ssh-attackers"
PIHUB_DIR = os.environ.get("PIHUB_DIR", "")


def _load_plugin():
    """Import the plugin module; skip when no Pi Hub checkout is available."""
    if PIHUB_DIR:
        sys.path.insert(0, PIHUB_DIR)
    try:
        spec = importlib.util.spec_from_file_location(
            "ssh_attackers_under_test", PLUGIN_DIR / "__init__.py")
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    except ImportError as exc:                      # pragma: no cover
        raise unittest.SkipTest(f"Pi Hub not importable: {exc}")


mod = _load_plugin()

NOW = 1_780_000_000.0
COOLDOWN = 60
CFG = {"cooldown_seconds": COOLDOWN, "min_attempts": 1, "poll_interval": 60}


def row(ip="92.118.39.77", age=0.0, attempts=43, country="Romania",
        city="Bucharest", isp="UNMANAGED LTD", asn="AS47890", rdns="–",
        users="root, admin"):
    return {"ip": ip, "_last": NOW - age, "attempts": attempts,
            "country": country, "city": city, "isp": isp, "asn": asn,
            "rdns": rdns, "users": users}


def snapshot(rows, at=NOW, error="", attempts=2905, unique=419, window=24):
    return {"rows": list(rows), "at": at, "error": error,
            "attempts": attempts, "unique": unique, "window": window}


class AlertSummaryTests(unittest.TestCase):
    def test_no_rows_means_no_alert(self):
        self.assertIsNone(mod.alert_summary(snapshot([]), NOW, CFG))

    def test_no_alert_once_the_cooldown_expired(self):
        snap = snapshot([row(age=COOLDOWN + 1)])
        self.assertIsNone(mod.alert_summary(snap, NOW, CFG))

    def test_alert_counts_down_to_zero(self):
        snap = snapshot([row(age=10), row(ip="1.2.3.4", age=20, attempts=2)])
        summary = mod.alert_summary(snap, NOW, CFG)
        self.assertEqual(summary["ips"], 2)
        self.assertEqual(summary["attempts"], 45)
        self.assertEqual(summary["age"], 10)
        self.assertEqual(summary["left"], 50)
        self.assertEqual(summary["pct"], 83)
        self.assertEqual(summary["newest"]["ip"], "92.118.39.77")

    def test_timestamp_from_the_future_counts_as_age_zero(self):
        snap = snapshot([row(age=-45)])
        summary = mod.alert_summary(snap, NOW, CFG)
        self.assertEqual(summary["age"], 0)
        self.assertEqual(summary["pct"], 100)

    def test_min_attempts_gates_the_alarm(self):
        snap = snapshot([row(age=5, attempts=1)])
        self.assertIsNotNone(mod.alert_summary(snap, NOW, CFG))
        self.assertIsNone(mod.alert_summary(snap, NOW, {**CFG, "min_attempts": 2}))


class MonitorStateTests(unittest.TestCase):
    def test_starting_before_the_first_read(self):
        self.assertEqual(mod.monitor_state({}, NOW, CFG), "starting")

    def test_idle_when_the_newest_attempt_is_old(self):
        self.assertEqual(
            mod.monitor_state(snapshot([row(age=600)]), NOW, CFG), "idle")

    def test_active_while_the_cooldown_runs(self):
        self.assertEqual(
            mod.monitor_state(snapshot([row(age=5)]), NOW, CFG), "active")

    def test_offline_only_after_a_stale_error(self):
        fresh_error = snapshot([], at=NOW - 10, error="unreachable")
        self.assertEqual(mod.monitor_state(fresh_error, NOW, CFG), "idle")
        stale_error = snapshot([], at=NOW - 3 * CFG["poll_interval"] - 1,
                              error="unreachable")
        self.assertEqual(mod.monitor_state(stale_error, NOW, CFG), "offline")


class NodeTests(unittest.TestCase):
    def test_pill_node_carries_state_count_and_cooldown(self):
        node = mod.pill_node(mod.alert_summary(snapshot([row(age=12)]), NOW, CFG), CFG)
        kinds = [c["type"] for c in node["children"]]
        self.assertEqual(node["dir"], "row")
        self.assertEqual(kinds, ["status", "badge", "progress"])
        self.assertEqual(node["children"][0]["state"], "bad")
        self.assertIn("1 IP · 43 Versuche", node["children"][1]["text"])
        self.assertEqual(node["children"][2]["text"], "noch 48 s")

    def test_offline_node_says_the_monitor_is_blind(self):
        node = mod.offline_node(snapshot([], error="unreachable"), CFG)
        self.assertEqual(node["type"], "status")
        self.assertEqual(node["state"], "unknown")

    def test_tab_node_rows_never_carry_none(self):
        node = mod.tab_node(snapshot([row(), row(ip="1.2.3.4", users="")]),
                            NOW, CFG)
        table = node["children"][1]
        self.assertEqual(table["type"], "table")
        self.assertEqual([c["key"] for c in table["columns"]][:3],
                         ["ip", "last_seen", "attempts"])
        for entry in table["rows"]:
            self.assertEqual(entry["_id"], entry["ip"])
            for key, value in entry.items():
                self.assertIsNotNone(value, f"{key} is None")


class ConfigTests(unittest.TestCase):
    def test_base_url_must_be_bare_host_and_port(self):
        for bad in ("", "https://host:9101", "http://host:9101/path",
                    "http://user@host", "http://host\r\nX: 1"):
            self.assertFalse(mod.valid_base_url(bad), bad)

    def test_base_url_accepts_host_and_port(self):
        self.assertTrue(mod.valid_base_url("http://100.100.100.1:9101"))
        self.assertTrue(mod.valid_base_url("http://collector.lan"))

    def test_clamp_falls_back_on_garbage(self):
        self.assertEqual(mod._clamp("x", 1, 10, 7), 7)
        self.assertEqual(mod._clamp(99, 1, 10, 7), 10)
        self.assertEqual(mod._clamp(5, 1, 10, 7), 5)


class _CollectorHandler(BaseHTTPRequestHandler):
    payload: dict = {}

    def do_GET(self):                             # noqa: N802 (stdlib name)
        body = json.dumps(type(self).payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _StubContext:
    """Duck-typed PluginContext: the plugin only reads and writes config."""

    def __init__(self, config: dict):
        self._config = dict(config)
        self.saved = 0

    def get_config(self) -> dict:
        return self._config

    def save_config(self) -> None:
        self.saved += 1


class LiveIntegrationTests(unittest.TestCase):
    """The refresher against a real HTTP collector, geo/DNS stubbed out."""

    def setUp(self):
        _CollectorHandler.payload = {"window_hours": 24, "total_attempts": 2905,
                                     "unique_ips": 419, "attackers": []}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _CollectorHandler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

        self.plugin = mod.SshAttackersPlugin()
        self.ctx = _StubContext({**mod.DEFAULT_CONFIG, "collector_url": self.base,
                                 "poll_interval": 10, "active_poll_interval": 5,
                                 "cooldown_seconds": 60})
        self._real_lookup = mod.SshAttackersPlugin._lookup
        self._real_rdns = mod.SshAttackersPlugin._reverse_dns
        mod.SshAttackersPlugin._lookup = lambda self, ip, cfg: {
            "country": "Romania", "city": "Bucharest", "isp": "UNMANAGED LTD",
            "asn": "AS47890", "rdns": "–"}
        mod.SshAttackersPlugin._reverse_dns = lambda self, ip: "–"
        self.plugin.load(self.ctx)
        self.addCleanup(self._teardown)

    def _teardown(self):
        self.plugin.unload()
        mod.SshAttackersPlugin._lookup = self._real_lookup
        mod.SshAttackersPlugin._reverse_dns = self._real_rdns
        self.server.shutdown()
        self.server.server_close()

    def _publish(self, ages):
        now = datetime.now(timezone.utc)
        _CollectorHandler.payload["attackers"] = [
            {"ip": f"92.118.39.{i}",
             "last_seen": datetime.fromtimestamp(now.timestamp() - age, timezone.utc)
                          .strftime("%Y-%m-%dT%H:%M:%SZ"),
             "attempts": 3 + i, "users": ["root", "admin"]}
            for i, age in enumerate(ages)]

    def test_pill_hidden_until_an_attack_arrives(self):
        self._publish([3600])
        self.plugin._refresh_once()
        self.assertIsNone(self.plugin.provider_pill())

    def test_pill_appears_with_a_running_cooldown(self):
        self._publish([4, 9])
        self.plugin._refresh_once()
        node = self.plugin.provider_pill()
        self.assertIsNotNone(node)
        self.assertEqual(node["children"][0]["text"], "SSH-Attack")
        self.assertIn("2 IPs", node["children"][1]["text"])
        # Singular reads "1 IP", not "1 IPs".
        one = mod.pill_node(mod.alert_summary(snapshot([row(age=3)]), NOW, CFG), CFG)
        self.assertIn("1 IP · 43 Versuche", one["children"][1]["text"])
        # The wall clock ticks between refresh and read, so assert the two
        # numbers agree with each other rather than a fixed countdown.
        age = int(node["children"][1]["text"].rsplit("vor ", 1)[1].split(" ")[0])
        self.assertEqual(node["children"][2]["text"], f"noch {60 - age} s")

    def test_pill_disappears_when_the_attack_ages_out(self):
        self._publish([4])
        self.plugin._refresh_once()
        self.assertIsNotNone(self.plugin.provider_pill())
        with self.plugin._lock:
            self.plugin._snapshot["rows"][0]["_last"] -= 120
        self.assertIsNone(self.plugin.provider_pill())

    def test_refresher_polls_fast_only_while_active(self):
        self._publish([3600])
        self.assertEqual(self.plugin._refresh_once(), 10.0)
        self._publish([2])
        self.assertEqual(self.plugin._refresh_once(), 5.0)

    def test_unreachable_collector_is_reported_not_hidden(self):
        self.plugin._store_error("invalid collector_url")
        with self.plugin._lock:
            self.plugin._snapshot["at"] = time.time() - 400
        node = self.plugin.provider_pill()
        self.assertEqual(node["text"], "SSH-Monitor offline")


class ManifestTests(unittest.TestCase):
    def test_manifest_caps_match_the_class(self):
        manifest = json.loads((PLUGIN_DIR / "pihub-plugin.json").read_text())
        self.assertEqual(manifest["capabilities"], mod.SshAttackersPlugin.capabilities)
        self.assertEqual(manifest["version"], mod.SshAttackersPlugin.version)
        self.assertEqual(manifest["plugin_api_version"],
                         mod.SshAttackersPlugin.plugin_api_version)

    def test_source_ships_no_private_or_tailnet_address(self):
        source = (PLUGIN_DIR / "__init__.py").read_text()
        self.assertEqual(mod.DEFAULT_CONFIG["collector_url"], "")
        leaked = re.findall(r"\b(?:10|192\.168|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))"
                            r"\.\d{1,3}\.\d{1,3}\b", source)
        self.assertEqual(leaked, [], f"private/tailnet address in source: {leaked}")


if __name__ == "__main__":
    unittest.main()
