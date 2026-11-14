# Changelog

## 1.2.0

- Every setting is now in the Configure dialog, grouped into Collector, Alert
  and Enrichment sections. The collector URL is a `url` field.
- New settings: lookup on/off, lookup URL template, lookup timeout, reverse DNS
  on/off, reverse DNS timeout.
- Changes apply live: the plugin polls immediately and drops stale cache entries.
- The collector URL may now be `https://` as well as `http://`.
- `migrate_config` fills the new settings and keeps existing values, so
  upgrades need no manual step.
- Requires Pi Hub 8.3.0. Capabilities are unchanged.

## 1.1.0

- Topbar attack alert with cooldown, plugin API v2.
