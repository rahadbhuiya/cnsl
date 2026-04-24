"""
cnsl/validator.py — Config validation with clear error messages.

Validates the loaded config dict against expected types and ranges.
Called at startup before any components are initialized.

Returns a list of error strings — empty list means config is valid.
"""

from __future__ import annotations

from typing import Any, Dict, List


def validate_config(cfg: Dict[str, Any]) -> List[str]:
    """
    Validate config dict. Returns list of error strings.
    Empty list = valid.
    """
    errors: List[str] = []
    v = _Validator(cfg, errors)

    # ── Sources ───────────────────────────────────────────────────────────────
    v.is_str("authlog_path")
    v.is_str("iface")
    v.is_bool("tcpdump_enabled")

    # ── Thresholds ────────────────────────────────────────────────────────────
    th = cfg.get("thresholds", {})
    if not isinstance(th, dict):
        errors.append("thresholds must be a dict")
    else:
        tv = _Validator(th, errors, prefix="thresholds")
        tv.is_positive_int("fails_window_sec",              max_val=3600)
        tv.is_positive_int("fails_threshold",               max_val=1000)
        tv.is_positive_int("unique_users_threshold",        max_val=100)
        tv.is_positive_int("success_after_fails_threshold", max_val=100)
        tv.is_positive_int("incident_cooldown_sec",         max_val=86400)

    # ── Actions ───────────────────────────────────────────────────────────────
    ac = cfg.get("actions", {})
    if not isinstance(ac, dict):
        errors.append("actions must be a dict")
    else:
        av = _Validator(ac, errors, prefix="actions")
        av.is_bool("dry_run")
        av.is_positive_int("block_duration_sec", max_val=86400 * 30)
        av.is_one_of("block_backend", ["iptables", "ipset"])
        av.is_str("chain")

    # ── Allowlist ─────────────────────────────────────────────────────────────
    al = cfg.get("allowlist", [])
    if not isinstance(al, list):
        errors.append("allowlist must be a list")
    else:
        import ipaddress
        for i, entry in enumerate(al):
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                errors.append(f"allowlist[{i}]: invalid IP/CIDR: {entry!r}")

    # ── Logging ───────────────────────────────────────────────────────────────
    lg = cfg.get("logging", {})
    if isinstance(lg, dict):
        lv = _Validator(lg, errors, prefix="logging")
        lv.is_str("json_log_path")
        lv.is_bool("console_verbose")

    # ── Auth ──────────────────────────────────────────────────────────────────
    auth = cfg.get("auth", {})
    if isinstance(auth, dict) and auth.get("enabled"):
        if not auth.get("secret_key"):
            errors.append(
                "auth.secret_key is required when auth.enabled=true. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        elif len(auth["secret_key"]) < 32:
            errors.append("auth.secret_key must be at least 32 characters")

    # ── Dashboard ─────────────────────────────────────────────────────────────
    dash = cfg.get("dashboard", {})
    if isinstance(dash, dict):
        port = dash.get("port", 8765)
        if not isinstance(port, int) or not (1024 <= port <= 65535):
            errors.append(f"dashboard.port must be between 1024 and 65535 (got {port!r})")

    # ── Notifications ─────────────────────────────────────────────────────────
    notif = cfg.get("notifications", {})
    if isinstance(notif, dict):
        min_sev = notif.get("min_severity", "MEDIUM")
        if min_sev not in ("HIGH", "MEDIUM", "LOW"):
            errors.append(f"notifications.min_severity must be HIGH, MEDIUM, or LOW (got {min_sev!r})")

        tg = notif.get("telegram", {})
        if isinstance(tg, dict) and tg.get("enabled"):
            if not tg.get("bot_token"):
                errors.append("notifications.telegram.bot_token is required when enabled")
            if not tg.get("chat_id"):
                errors.append("notifications.telegram.chat_id is required when enabled")

        dc = notif.get("discord", {})
        if isinstance(dc, dict) and dc.get("enabled"):
            if not dc.get("webhook_url"):
                errors.append("notifications.discord.webhook_url is required when enabled")

    return errors


def validate_and_exit(cfg: Dict[str, Any]) -> None:
    """Validate config and print errors + exit if invalid."""
    errors = validate_config(cfg)
    if errors:
        print("\n[CNSL] Config validation failed:\n")
        for e in errors:
            print(f"  ✗  {e}")
        print("\nFix the errors above and restart.\n")
        raise SystemExit(1)



# Internal helper


class _Validator:
    def __init__(self, d: Dict, errors: List[str], prefix: str = ""):
        self._d      = d
        self._errors = errors
        self._prefix = prefix

    def _key(self, k: str) -> str:
        return f"{self._prefix}.{k}" if self._prefix else k

    def is_str(self, key: str, required: bool = False) -> None:
        val = self._d.get(key)
        if val is None:
            if required:
                self._errors.append(f"{self._key(key)} is required")
            return
        if not isinstance(val, str):
            self._errors.append(f"{self._key(key)} must be a string (got {type(val).__name__})")
        elif required and not val.strip():
            self._errors.append(f"{self._key(key)} must not be empty")

    def is_bool(self, key: str) -> None:
        val = self._d.get(key)
        if val is not None and not isinstance(val, bool):
            self._errors.append(f"{self._key(key)} must be true or false (got {val!r})")

    def is_positive_int(self, key: str, max_val: int = 1_000_000) -> None:
        val = self._d.get(key)
        if val is None:
            return
        if not isinstance(val, int) or isinstance(val, bool):
            self._errors.append(f"{self._key(key)} must be an integer (got {val!r})")
            return
        if val <= 0:
            self._errors.append(f"{self._key(key)} must be > 0 (got {val})")
        elif val > max_val:
            self._errors.append(f"{self._key(key)} must be <= {max_val} (got {val})")

    def is_one_of(self, key: str, choices: list) -> None:
        val = self._d.get(key)
        if val is not None and val not in choices:
            self._errors.append(
                f"{self._key(key)} must be one of {choices} (got {val!r})"
            )