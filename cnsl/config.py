"""
cnsl/config.py — Configuration loading, merging, and validation.

Priority (highest → lowest):
  CLI flags  >  config file  >  DEFAULT_CONFIG

Supported formats: JSON, YAML (requires pyyaml).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Default configuration (all tuneable values live here)
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: Dict[str, Any] = {
    # ── Sources ──────────────────────────────────────────────────────────────
    "authlog_path":    "/var/log/auth.log",
    "iface":           "any",
    "tcpdump_enabled": True,

    # Narrow BPF keeps CPU low in production.
    "tcpdump_bpf": (
        "tcp port 22 or tcp port 445 or tcp port 139 "
        "or udp port 5353 or arp"
    ),

    # ── Detection thresholds (per source IP) ─────────────────────────────────
    "thresholds": {
        # Brute-force: many failures in a short window
        "fails_window_sec":  60,
        "fails_threshold":   8,

        # Credential-stuffing: many distinct usernames tried
        "unique_users_threshold": 4,

        # Credential-breach: success after many failures (likely stolen creds)
        "success_after_fails_threshold": 5,

        # Suppress repeated incidents per IP (avoids alert storms)
        "incident_cooldown_sec": 120,
    },

    # ── Blocking ─────────────────────────────────────────────────────────────
    "actions": {
        "dry_run":            True,    # SAFE DEFAULT — flip to false to enable real blocks
        "block_duration_sec": 900,     # 15-minute temporary block
        "block_backend":      "iptables",  # "iptables" | "ipset"
        "ipset_name":         "cnsl_blocklist",
        "chain":              "INPUT",
    },

    # ── Allowlist — these IPs are NEVER blocked ───────────────────────────────
    "allowlist": [
        "127.0.0.1",
        "::1",
    ],

    # ── Logging ──────────────────────────────────────────────────────────────
    "logging": {
        "json_log_path":   "./cnsl_guard.jsonl",
        "console_verbose": True,
        "log_net_hints":   False,   # set True to see raw tcpdump events (noisy)
    },

    # ── REST API ──────────────────────────────────────────────────────────────
    "api": {
        "enabled": False,
        "host":    "127.0.0.1",
        "port":    8765,
    },
}


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Return merged config (defaults + optional file overrides)."""
    cfg: Dict[str, Any] = _deep_copy(DEFAULT_CONFIG)

    if not path:
        return cfg

    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    user_cfg = _read_file(path)
    return _deep_merge(cfg, user_cfg)


def apply_cli_overrides(cfg: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
    """Overlay explicit CLI flags on top of loaded config."""
    if kwargs.get("execute"):
        cfg["actions"]["dry_run"] = False
    if kwargs.get("no_tcpdump"):
        cfg["tcpdump_enabled"] = False
    if kwargs.get("iface"):
        cfg["iface"] = kwargs["iface"]
    if kwargs.get("authlog"):
        cfg["authlog_path"] = kwargs["authlog"]
    if kwargs.get("api"):
        cfg["api"]["enabled"] = True
    return cfg


def safe_int(x: Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

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