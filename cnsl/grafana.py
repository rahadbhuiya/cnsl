"""
cnsl/grafana.py — Grafana dashboard template generator.

Generates a Grafana dashboard JSON that visualises CNSL metrics.
Import it via Grafana UI: Dashboards → Import → paste JSON.

Requires:
  - CNSL running with --dashboard flag
  - Prometheus scraping http://localhost:8765/api/metrics
  - Grafana connected to that Prometheus datasource

Usage:
  python -m cnsl --grafana-export > cnsl_dashboard.json
  # or via API:
  reporter = GrafanaDashboard(datasource_name="Prometheus")
  json_str = reporter.generate()
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List



# Panel builders


def _stat_panel(
    title:    str,
    metric:   str,
    unit:     str  = "short",
    color:    str  = "green",
    grid_pos: Dict = None,
    pid:      int  = 1,
) -> Dict:
    return {
        "id":       pid,
        "type":     "stat",
        "title":    title,
        "gridPos":  grid_pos or {"h": 4, "w": 6, "x": 0, "y": 0},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"]},
            "colorMode":     "background",
            "graphMode":     "area",
            "textMode":      "auto",
        },
        "fieldConfig": {
            "defaults": {
                "unit":  unit,
                "color": {"mode": "thresholds"},
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": color, "value": None},
                    ],
                },
            },
        },
        "targets": [{
            "expr":         metric,
            "legendFormat": title,
            "refId":        "A",
        }],
    }


def _timeseries_panel(
    title:    str,
    targets:  List[Dict],
    unit:     str  = "short",
    grid_pos: Dict = None,
    pid:      int  = 10,
) -> Dict:
    return {
        "id":      pid,
        "type":    "timeseries",
        "title":   title,
        "gridPos": grid_pos or {"h": 8, "w": 12, "x": 0, "y": 4},
        "options": {
            "tooltip": {"mode": "multi"},
            "legend":  {"displayMode": "list", "placement": "bottom"},
        },
        "fieldConfig": {
            "defaults": {
                "unit":   unit,
                "custom": {
                    "lineWidth":   2,
                    "fillOpacity": 10,
                    "spanNulls":   True,
                },
            },
        },
        "targets": targets,
    }


def _bar_gauge_panel(
    title:    str,
    metric:   str,
    label:    str,
    grid_pos: Dict = None,
    pid:      int  = 20,
) -> Dict:
    return {
        "id":      pid,
        "type":    "bargauge",
        "title":   title,
        "gridPos": grid_pos or {"h": 8, "w": 12, "x": 12, "y": 4},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"]},
            "orientation":   "horizontal",
            "displayMode":   "gradient",
        },
        "fieldConfig": {
            "defaults": {
                "unit":  "short",
                "color": {"mode": "continuous-RdYlGr"},
            },
        },
        "targets": [{
            "expr":         metric,
            "legendFormat": f"{{{{ {label} }}}}",
            "refId":        "A",
        }],
    }


def _table_panel(
    title:    str,
    targets:  List[Dict],
    grid_pos: Dict = None,
    pid:      int  = 30,
) -> Dict:
    return {
        "id":      pid,
        "type":    "table",
        "title":   title,
        "gridPos": grid_pos or {"h": 8, "w": 24, "x": 0, "y": 20},
        "options": {
            "sortBy": [{"displayName": "Value", "desc": True}],
        },
        "fieldConfig": {
            "defaults": {"custom": {"align": "auto"}},
        },
        "targets": targets,
    }


def _row_panel(title: str, y: int, pid: int) -> Dict:
    return {
        "id":      pid,
        "type":    "row",
        "title":   title,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
        "collapsed": False,
    }



# Full dashboard


class GrafanaDashboard:
    """
    Generates a complete Grafana dashboard JSON for CNSL metrics.
    """

    def __init__(self, datasource_name: str = "Prometheus"):
        self.datasource = datasource_name

    def generate(self) -> str:
        """Return JSON string of the full Grafana dashboard."""
        dashboard = {
            "title":       "CNSL — Correlated Network Security Layer",
            "description": "Real-time security monitoring dashboard for CNSL",
            "tags":        ["cnsl", "security", "intrusion-detection"],
            "timezone":    "browser",
            "refresh":     "30s",
            "time":        {"from": "now-24h", "to": "now"},
            "schemaVersion": 38,
            "version":       1,
            "uid":           "cnsl-main",

            "__inputs": [{
                "name":        "DS_PROMETHEUS",
                "label":       "Prometheus",
                "type":        "datasource",
                "pluginId":    "prometheus",
                "pluginName":  "Prometheus",
            }],

            "__requires": [
                {"type": "grafana",    "id": "grafana",    "name": "Grafana",    "version": "10.0.0"},
                {"type": "datasource", "id": "prometheus", "name": "Prometheus", "version": "1.0.0"},
                {"type": "panel",      "id": "stat",       "name": "Stat",       "version": ""},
                {"type": "panel",      "id": "timeseries", "name": "Time series","version": ""},
                {"type": "panel",      "id": "bargauge",   "name": "Bar gauge",  "version": ""},
                {"type": "panel",      "id": "table",      "name": "Table",      "version": ""},
            ],

            "templating": {
                "list": [{
                    "name":       "datasource",
                    "type":       "datasource",
                    "label":      "Datasource",
                    "pluginId":   "prometheus",
                    "current":    {},
                    "options":    [],
                    "query":      "prometheus",
                    "refresh":    1,
                }],
            },

            "panels": self._build_panels(),
        }
        return json.dumps(dashboard, indent=2)

    def _build_panels(self) -> List[Dict]:
        panels = []
        pid    = 1

        # ── Row: Overview ─────────────────────────────────────────────────────
        panels.append(_row_panel("Overview", y=0, pid=pid)); pid += 1

        stat_defs = [
            ("Total incidents",  "cnsl_incidents_total",         "short",   "red",    0),
            ("HIGH severity",    'cnsl_incidents_total{severity="HIGH"}', "short", "dark-red", 6),
            ("Active blocks",    "cnsl_blocks_active",            "short",   "orange", 12),
            ("SSH failures",     "cnsl_ssh_fails_total",          "short",   "yellow", 18),
        ]
        for title, metric, unit, color, x in stat_defs:
            panels.append(_stat_panel(
                title=title, metric=metric, unit=unit, color=color,
                grid_pos={"h": 4, "w": 6, "x": x, "y": 1},
                pid=pid,
            ))
            pid += 1

        # ── Row: Trends ───────────────────────────────────────────────────────
        panels.append(_row_panel("Trends", y=5, pid=pid)); pid += 1

        panels.append(_timeseries_panel(
            title="Incidents over time",
            targets=[
                {"expr": 'rate(cnsl_incidents_total{severity="HIGH"}[5m])*300',
                 "legendFormat": "HIGH",   "refId": "A"},
                {"expr": 'rate(cnsl_incidents_total{severity="MEDIUM"}[5m])*300',
                 "legendFormat": "MEDIUM", "refId": "B"},
            ],
            unit="short",
            grid_pos={"h": 8, "w": 12, "x": 0, "y": 6},
            pid=pid,
        ))
        pid += 1

        panels.append(_timeseries_panel(
            title="SSH failures rate",
            targets=[{
                "expr":         "rate(cnsl_ssh_fails_total[5m])*60",
                "legendFormat": "fails/min",
                "refId":        "A",
            }],
            unit="short",
            grid_pos={"h": 8, "w": 12, "x": 12, "y": 6},
            pid=pid,
        ))
        pid += 1

        panels.append(_timeseries_panel(
            title="Active blocks",
            targets=[{
                "expr":         "cnsl_blocks_active",
                "legendFormat": "blocked IPs",
                "refId":        "A",
            }],
            unit="short",
            grid_pos={"h": 8, "w": 12, "x": 0, "y": 14},
            pid=pid,
        ))
        pid += 1

        panels.append(_timeseries_panel(
            title="Events processed",
            targets=[{
                "expr":         "rate(cnsl_events_processed_total[1m])*60",
                "legendFormat": "events/min",
                "refId":        "A",
            }],
            unit="short",
            grid_pos={"h": 8, "w": 12, "x": 12, "y": 14},
            pid=pid,
        ))
        pid += 1

        # ── Row: Top attackers ────────────────────────────────────────────────
        panels.append(_row_panel("Top Attackers", y=22, pid=pid)); pid += 1

        panels.append(_bar_gauge_panel(
            title="Top attacker IPs (fail count)",
            metric="cnsl_ip_fails_total",
            label="ip",
            grid_pos={"h": 10, "w": 12, "x": 0, "y": 23},
            pid=pid,
        ))
        pid += 1

        panels.append(_bar_gauge_panel(
            title="Attacks by country",
            metric="sum by (country) (cnsl_ip_fails_total)",
            label="country",
            grid_pos={"h": 10, "w": 12, "x": 12, "y": 23},
            pid=pid,
        ))
        pid += 1

        # ── Row: System ───────────────────────────────────────────────────────
        panels.append(_row_panel("System", y=33, pid=pid)); pid += 1

        panels.append(_timeseries_panel(
            title="CNSL uptime",
            targets=[{
                "expr":         "cnsl_uptime_seconds",
                "legendFormat": "uptime",
                "refId":        "A",
            }],
            unit="s",
            grid_pos={"h": 6, "w": 8, "x": 0, "y": 34},
            pid=pid,
        ))
        pid += 1

        panels.append(_stat_panel(
            title="Total blocks (all time)",
            metric="cnsl_blocks_total",
            unit="short",
            color="blue",
            grid_pos={"h": 6, "w": 8, "x": 8, "y": 34},
            pid=pid,
        ))
        pid += 1

        panels.append(_stat_panel(
            title="Uptime",
            metric="cnsl_uptime_seconds",
            unit="s",
            color="green",
            grid_pos={"h": 6, "w": 8, "x": 16, "y": 34},
            pid=pid,
        ))
        pid += 1

        return panels



# CLI export helper


def export_dashboard(output_path: str = "./cnsl_grafana_dashboard.json",
                     datasource:  str = "Prometheus") -> str:
    dash = GrafanaDashboard(datasource_name=datasource)
    json_str = dash.generate()
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_str)
    return output_path