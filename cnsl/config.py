"""
cnsl/config.py — Configuration loading, merging, and validation.

Priority (highest to lowest):
  CLI flags  >  config file  >  DEFAULT_CONFIG

Supported formats: JSON, YAML (requires pyyaml).
All Phase 1 + Phase 2 defaults live here.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional



# Default configuration — every tuneable value lives here


DEFAULT_CONFIG: Dict[str, Any] = {

    # ── Sources ───────────────────────────────────────────────────────────────
    "authlog_path":    "/var/log/auth.log",
    "iface":           "any",
    "tcpdump_enabled": True,

    # Narrow BPF keeps CPU low in production.
    "tcpdump_bpf": (
        "tcp port 22 or tcp port 445 or tcp port 139 "
        "or udp port 5353 or arp"
    ),

    # ── Multi-log sources (Phase 2) ───────────────────────────────────────────
    # Set path to enable; omit or set null to disable that source.
    "log_sources": {
        "nginx":    None,   # e.g. "/var/log/nginx/access.log"
        "apache":   None,
        "mysql":    None,
        "ufw":      None,
        "syslog":   None,
    },

    # ── Detection thresholds (per source IP) ──────────────────────────────────
    "thresholds": {
        # Brute-force: many failures in a short window
        "fails_window_sec":  60,
        "fails_threshold":   8,

        # Credential stuffing: many distinct usernames tried
        "unique_users_threshold": 4,

        # Credential breach: success after many failures
        "success_after_fails_threshold": 5,

        # Suppress repeated incidents per IP
        "incident_cooldown_sec": 120,

        # Web attack thresholds (Phase 2)
        "web_scan_threshold":       20,   # 404s / scan events before alert
        "web_auth_fail_threshold":  15,   # 401/403 before alert
        "db_fail_threshold":         5,   # DB auth fails before alert
    },

    # ── Blocking ──────────────────────────────────────────────────────────────
    "actions": {
        "dry_run":            True,       # SAFE DEFAULT
        "block_duration_sec": 900,        # 15-minute temporary block
        "block_backend":      "iptables", # "iptables" | "ipset"
        "ipset_name":         "cnsl_blocklist",
        "chain":              "INPUT",

        # Auto-escalate to HIGH block if repeat offender
        "repeat_offender_threshold": 3,   # incidents before escalating
        "repeat_offender_window_sec": 3600,
    },

    # ── Allowlist — never blocked ─────────────────────────────────────────────
    "allowlist": [
        "127.0.0.1",
        "::1",
    ],

    # ── GeoIP (Phase 1) ───────────────────────────────────────────────────────
    "geoip": {
        # Set mmdb_path to use MaxMind offline (faster, unlimited).
        # Download free from https://www.maxmind.com/en/geolite2/signup
        # Falls back to ip-api.com (online, 45 req/min) if not set.
        "mmdb_path": None,
    },

    # ── Authentication (Phase 1) ──────────────────────────────────────────────
    "auth": {
        "enabled":                    False,
        "secret_key":                 None,   # REQUIRED if enabled
        "access_token_expire_hours":  8,
        "refresh_token_expire_days":  7,
        "users":                      {},     # populated by user
    },

    # ── Redis distributed blocklist (Phase 2) ─────────────────────────────────
    "redis": {
        "enabled":      False,
        "host":         "127.0.0.1",
        "port":         6379,
        "password":     None,
        "db":           0,
        "key_prefix":   "cnsl",
        "sync_blocks":  True,
    },

    # ── Threat intelligence (Phase 2) ─────────────────────────────────────────
    "threat_intel": {
        "abuseipdb": {
            "enabled":         False,
            "api_key":         None,
            "auto_flag_score": 50,    # 0-100, flag IPs above this score
            "max_age_days":    30,
        },
    },

    # ── Behavioral baseline (Phase 2) ─────────────────────────────────────────
    "behavioral_baseline": {
        "enabled":           True,
        "min_observations":  10,      # learn before flagging
    },

    # ── Notifications ─────────────────────────────────────────────────────────
    "notifications": {
        "min_severity": "MEDIUM",

        "telegram": {
            "enabled":   False,
            "bot_token": None,
            "chat_id":   None,
        },
        "discord": {
            "enabled":     False,
            "webhook_url": None,
        },
        "slack": {
            "enabled":     False,
            "webhook_url": None,
        },
        "webhook": {
            "enabled":       False,
            "url":           None,
            "secret_header": "X-CNSL-Secret",
            "secret_value":  None,
        },
    },

    # ── SQLite persistence ────────────────────────────────────────────────────
    "store": {
        "db_path": "./cnsl_state.db",
    },

    # ── Logging ───────────────────────────────────────────────────────────────
    "logging": {
        "json_log_path":    "./cnsl.jsonl",
        "console_verbose":  True,
        "log_net_hints":    False,  # noisy — enable only for debugging
        "log_correlations": True,   # log correlation rule hits
        "log_baseline":     True,   # log behavioral anomalies
    },

    # ── Dashboard ─────────────────────────────────────────────────────────────
    "dashboard": {
        "enabled": True,
        "host":    "127.0.0.1",
        "port":    8765,
    },



    # ── Honeypot / active response (Phase 4) ──────────────────────────────────
    "honeypot": {
        "enabled":                 False,
        "mode":                    "redirect",  # drop|redirect|tarpit|log_only
        "honeypot_host":           "127.0.0.1",
        "honeypot_port":           2222,
        "fake_hostname":           "ubuntu-server",
        "fake_version":            "Ubuntu 22.04.3 LTS",
        "log_commands":            True,
        "auto_redirect_severity":  "HIGH",
    },

    # ── Asset inventory (Phase 4) ─────────────────────────────────────────────
    "asset_inventory": {
        "enabled": True,
    },

    # ── File Integrity Monitoring (Phase 3) ───────────────────────────────────
    "fim": {
        "enabled":          False,
        "db_path":          "./cnsl_fim.db",
        "scan_interval_sec": 300,
        "alert_on_delete":  True,
        "alert_on_create":  True,
        # Override watch_paths/watch_dirs to customise what is monitored.
        # Defaults are defined in fim.py (_DEFAULT_PATHS / _DEFAULT_DIRS).
    },

    # ── ML anomaly detection (Phase 3) ────────────────────────────────────────
    "ml": {
        "enabled":                  False,
        "min_samples":              100,
        "retrain_interval_sec":     3600,
        "contamination":            0.05,
        "anomaly_score_threshold": -0.1,
    },

    # ── Reporting (Phase 3) ───────────────────────────────────────────────────
    "reporting": {
        "output_dir": "./reports",
    },

    # ── Queue ─────────────────────────────────────────────────────────────────
    "queue": {
        "maxsize": 10000,   # drop events if queue fills (prevents OOM)
    },
}



# Public interface


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Return merged config (defaults + optional file overrides).

    Search order when no explicit path is given:
      1. /etc/cnsl/config.json
      2. /etc/cnsl/config.yaml
      3. ./config.json  (current working directory)
      4. Built-in defaults only
    """
    cfg: Dict[str, Any] = _deep_copy(DEFAULT_CONFIG)

    # Resolve path — explicit arg wins, then auto-discover
    resolved: Optional[str] = path
    if not resolved:
        candidates = [
            "/etc/cnsl/config.json",
            "/etc/cnsl/config.yaml",
            "/etc/cnsl/config.yml",
            os.path.join(os.getcwd(), "config.json"),
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                resolved = candidate
                break

    if not resolved:
        return cfg  # pure defaults

    if not os.path.exists(resolved):
        raise FileNotFoundError(f"Config file not found: {resolved}")

    user_cfg = _read_file(resolved)
    merged = _deep_merge(cfg, user_cfg)
    # Print which config was loaded so operators can confirm
    print(f"   Config loaded: {resolved}")
    return merged


def apply_cli_overrides(cfg: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
    """Overlay CLI flags on top of loaded config. CLI always wins."""

    # Blocking
    if kwargs.get("execute"):
        cfg["actions"]["dry_run"] = False

    # Sources
    if kwargs.get("no_tcpdump"):
        cfg["tcpdump_enabled"] = False
    if kwargs.get("iface"):
        cfg["iface"] = kwargs["iface"]
    if kwargs.get("authlog"):
        cfg["authlog_path"] = kwargs["authlog"]

    # Features
    if kwargs.get("no_geoip"):
        cfg["geoip"]["mmdb_path"] = None
        cfg["_no_geoip"]          = True
    if kwargs.get("no_db"):
        cfg["_no_db"] = True
    if kwargs.get("no_baseline"):
        cfg["behavioral_baseline"]["enabled"] = False

    # Dashboard / API
    if kwargs.get("api") or kwargs.get("dashboard"):
        cfg["dashboard"]["enabled"] = True

    # Backend override
    if kwargs.get("backend"):
        cfg["actions"]["block_backend"] = kwargs["backend"]

    return cfg



# Typed accessors — use these instead of cfg["key"] in engine code


def get_authlog_path(cfg: Dict) -> str:
    return cfg.get("authlog_path", "/var/log/auth.log")

def get_log_sources(cfg: Dict) -> Dict[str, str]:
    """Return {name: path} for enabled log sources (path is not None)."""
    sources = cfg.get("log_sources", {})
    return {
        name: path
        for name, path in sources.items()
        if path and isinstance(path, str) and not name.startswith("_")
    }

def get_allowlist(cfg: Dict) -> List[str]:
    return cfg.get("allowlist", ["127.0.0.1", "::1"])

def get_thresholds(cfg: Dict) -> Dict[str, Any]:
    return cfg.get("thresholds", DEFAULT_CONFIG["thresholds"])

def is_dry_run(cfg: Dict) -> bool:
    return bool(cfg.get("actions", {}).get("dry_run", True))

def get_db_path(cfg: Dict) -> str:
    return cfg.get("store", {}).get("db_path", "./cnsl_state.db")

def get_queue_maxsize(cfg: Dict) -> int:
    return safe_int(cfg.get("queue", {}).get("maxsize"), 10000)

def get_dashboard_cfg(cfg: Dict) -> Dict:
    return cfg.get("dashboard", DEFAULT_CONFIG["dashboard"])

def get_redis_cfg(cfg: Dict) -> Dict:
    return cfg.get("redis", DEFAULT_CONFIG["redis"])

def get_geoip_cfg(cfg: Dict) -> Dict:
    return cfg.get("geoip", DEFAULT_CONFIG["geoip"])

def get_auth_cfg(cfg: Dict) -> Dict:
    return cfg.get("auth", DEFAULT_CONFIG["auth"])

def get_threat_intel_cfg(cfg: Dict) -> Dict:
    return cfg.get("threat_intel", DEFAULT_CONFIG["threat_intel"])

def get_baseline_cfg(cfg: Dict) -> Dict:
    return cfg.get("behavioral_baseline", DEFAULT_CONFIG["behavioral_baseline"])

def get_notification_cfg(cfg: Dict) -> Dict:
    return cfg.get("notifications", DEFAULT_CONFIG["notifications"])



# Helpers


def safe_int(x: Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default


def safe_float(x: Any, default: float) -> float:
    try:
        return float(x)
    except Exception:
        return default


def safe_bool(x: Any, default: bool) -> bool:
    if isinstance(x, bool):
        return x
    if isinstance(x, str):
        return x.lower() in ("true", "1", "yes", "on")
    try:
        return bool(int(x))
    except Exception:
        return default



# Internals


def _deep_copy(d: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(d))


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def _read_file(path: str) -> Dict[str, Any]:
    if path.lower().endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    # YAML — optional dependency
    try:
        import yaml  # type: ignore
    except ImportError:
        raise RuntimeError(
            "YAML config provided but PyYAML is not installed.\n"
            "  pip install pyyaml   OR   use a .json config file."
        )
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}