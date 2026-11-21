"""
cnsl/metrics.py -- Prometheus-compatible metrics endpoint.

Exposes /metrics in text exposition format.
Scrape with Prometheus -> visualize in Grafana.

Metrics exposed:
  cnsl_incidents_total{severity}        -- total incidents by severity
  cnsl_blocks_active                    -- currently blocked IPs
  cnsl_blocks_total                     -- all-time blocks
  cnsl_ssh_fails_total                  -- all SSH failures seen
  cnsl_events_processed_total           -- total events processed
  cnsl_top_attacker_fails{ip,country}   -- per-IP fail count (top 10)
"""

from __future__ import annotations

import time
from typing import Any, Dict


class Metrics:
    """Simple in-process counters, exported as Prometheus text."""

    def __init__(self):
        self._start = time.time()
        self._last_event_ts: float = 0.0

        # Counters
        self.incidents_total:   Dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.blocks_total:      int = 0
        self.ssh_fails_total:   int = 0
        self.events_processed:  int = 0

        # Gauges
        self.blocks_active:     int = 0

        # Per-IP top fails (kept small)
        self.ip_fails:          Dict[str, int] = {}
        self.ip_country:        Dict[str, str] = {}
        self.observability_sources: Dict[str, Dict[str, Any]] = {}

    # Update methods 

    def inc_incident(self, severity: str) -> None:
        self.incidents_total[severity] = self.incidents_total.get(severity, 0) + 1

    def inc_block(self) -> None:
        self.blocks_total += 1
        self.blocks_active += 1

    def dec_block(self) -> None:
        self.blocks_active = max(0, self.blocks_active - 1)

    def inc_ssh_fail(self, ip: str, country: str = "") -> None:
        self.ssh_fails_total += 1
        self.ip_fails[ip] = self.ip_fails.get(ip, 0) + 1
        if country:
            self.ip_country[ip] = country
        # Keep only top 50 IPs to limit cardinality
        if len(self.ip_fails) > 50:
            min_ip = min(self.ip_fails, key=self.ip_fails.get)
            self.ip_fails.pop(min_ip, None)
            self.ip_country.pop(min_ip, None)

    def inc_event(self) -> None:
        self.events_processed += 1
        self._last_event_ts = time.time()

    # Exposition 

    def render(self) -> str:
        """Return Prometheus text exposition format."""
        lines = []

        def gauge(name: str, value: Any, help_: str, labels: str = "") -> None:
            lines.append(f"# HELP {name} {help_}")
            lines.append(f"# TYPE {name} gauge")
            label_str = f"{{{labels}}}" if labels else ""
            lines.append(f"{name}{label_str} {value}")

        def counter(name: str, value: Any, help_: str, labels: str = "") -> None:
            lines.append(f"# HELP {name} {help_}")
            lines.append(f"# TYPE {name} counter")
            label_str = f"{{{labels}}}" if labels else ""
            lines.append(f"{name}_total{label_str} {value}")

        uptime = int(time.time() - self._start)
        gauge("cnsl_uptime_seconds", uptime, "Seconds since CNSL started")

        lines.append("# HELP cnsl_incidents_total Total incidents by severity")
        lines.append("# TYPE cnsl_incidents_total counter")
        for sev, count in self.incidents_total.items():
            lines.append(f'cnsl_incidents_total{{severity="{sev}"}} {count}')

        gauge("cnsl_blocks_active",  self.blocks_active,   "Currently blocked IPs")
        counter("cnsl_blocks",       self.blocks_total,    "All-time blocks executed")
        counter("cnsl_ssh_fails",    self.ssh_fails_total, "Total SSH failures seen")
        counter("cnsl_events_processed", self.events_processed, "Total events processed")

        # Top attacker IPs (top 10 by fail count)
        top = sorted(self.ip_fails.items(), key=lambda x: x[1], reverse=True)[:10]
        if top:
            lines.append("# HELP cnsl_ip_fails_total SSH failures per attacker IP")
            lines.append("# TYPE cnsl_ip_fails_total counter")
            for ip, count in top:
                country = self.ip_country.get(ip, "")
                lines.append(
                    f'cnsl_ip_fails_total{{ip="{ip}",country="{country}"}} {count}'
                )

        # Remote source metrics use bounded profile labels; never expose URLs,
        # tenant credentials, or query text in the Prometheus endpoint.
        def label(value: str) -> str:
            return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        lines.extend([
            "# HELP cnsl_source_requests_total Remote source polling requests",
            "# TYPE cnsl_source_requests_total counter",
            "# HELP cnsl_source_events_total Remote source records by parse result",
            "# TYPE cnsl_source_events_total counter",
            "# HELP cnsl_source_parse_errors_total Remote source records that failed parsing",
            "# TYPE cnsl_source_parse_errors_total counter",
            "# HELP cnsl_source_lag_seconds Latest remote event ingestion lag",
            "# TYPE cnsl_source_lag_seconds gauge",
            "# HELP cnsl_source_deduplicated_total Remote source duplicate records",
            "# TYPE cnsl_source_deduplicated_total counter",
            "# HELP cnsl_source_checkpoint_age_seconds Seconds since checkpoint update",
            "# TYPE cnsl_source_checkpoint_age_seconds gauge",
            "# HELP cnsl_source_backpressure_total Remote queue backpressure events",
            "# TYPE cnsl_source_backpressure_total counter",
        ])
        for profile, stat in self.observability_sources.items():
            labels = f'transport="loki",profile="{label(profile)}"'
            lines.append(f'cnsl_source_requests_total{{{labels},status="success"}} {stat.get("last_success_count", 0)}')
            lines.append(f'cnsl_source_requests_total{{{labels},status="error"}} {stat.get("request_errors", 0)}')
            lines.append(f'cnsl_source_events_total{{{labels},result="parsed"}} {stat.get("parsed", 0)}')
            lines.append(f'cnsl_source_events_total{{{labels},result="rejected"}} {stat.get("rejected", 0)}')
            lines.append(f'cnsl_source_parse_errors_total{{{labels},parser="{label(stat.get("parser", "json_security"))}"}} {stat.get("rejected", 0)}')
            lines.append(f'cnsl_source_deduplicated_total{{{labels}}} {stat.get("deduplicated", 0)}')
            lines.append(f'cnsl_source_backpressure_total{{{labels}}} {stat.get("queue_backpressure", 0)}')
            lines.append(f'cnsl_source_lag_seconds{{{labels}}} {stat.get("lag_sec", 0.0)}')
            updated = stat.get("checkpoint_updated")
            age = max(0, time.time() - updated) if updated else 0
            lines.append(f'cnsl_source_checkpoint_age_seconds{{profile="{label(profile)}"}} {age:.3f}')

        return "\n".join(lines) + "\n"