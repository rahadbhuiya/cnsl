"""
cnsl/validator.py -- Config validation with clear error messages.

Validates the loaded config dict against expected types and ranges.
Called at startup before any components are initialized.

Also used by `cnsl --validate-config` to check a config file without
starting the detection engine.

Returns a list of ValidationError objects -- empty list means valid.
Each error has:
  - path:    dot-separated config key (e.g. "auth.secret_key")
  - message: human-readable description of the problem
  - level:   "error" (must fix) or "warning" (should review)
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional



# ValidationError


@dataclass
class ValidationError:
    path:    str
    message: str
    level:   str = "error"   # "error" or "warning"

    def __str__(self) -> str:
        tag = "ERROR  " if self.level == "error" else "WARN   "
        return f"{tag} {self.path}: {self.message}"



# Public API

def validate_config(cfg: Dict[str, Any]) -> List[ValidationError]:
    """
    Validate config dict. Returns list of ValidationError objects.
    Empty list = valid (no errors or warnings).
    """
    issues: List[ValidationError] = []
    v = _V(cfg, issues)

    # Core source paths
    v.is_str("authlog_path")
    v.is_str("iface")
    v.is_bool("tcpdump_enabled")

    # Thresholds (legacy block)
    _validate_thresholds(cfg.get("thresholds", {}), issues)

    # Actions
    _validate_actions(cfg.get("actions", {}), issues)

    # Allowlist
    _validate_allowlist(cfg.get("allowlist", []), issues)

    # Store / database backend
    _validate_store(cfg.get("store", {}), issues)

    # Logging
    _validate_logging(cfg.get("logging", {}), issues)

    # Dashboard auth
    _validate_auth(cfg.get("auth", {}), issues)

    # Dashboard
    _validate_dashboard(cfg.get("dashboard", {}), issues)

    # Notifications
    _validate_notifications(cfg.get("notifications", {}), issues)

    # Redis
    _validate_redis(cfg.get("redis", {}), issues)

    # ML
    _validate_ml(cfg.get("ml", {}), issues)

    # Kill chain
    _validate_kill_chain(cfg.get("kill_chain", {}), issues)

    # Pattern learning
    _validate_pattern_learning(cfg.get("pattern_learning", {}), issues)

    # SIEM connectors
    _validate_siem(cfg.get("siem", {}), issues)

    # Federation
    _validate_federation(cfg.get("federation", {}), issues)

    # Cloud identity
    _validate_cloud_identity(cfg.get("cloud_identity", {}), issues)

    # Zero-trust
    _validate_zero_trust(cfg.get("zero_trust", {}), issues)

    # OT/IoT
    _validate_ot(cfg.get("ot", {}), issues)

    # Rules block (per-rule overrides)
    _validate_rules(cfg.get("rules", {}), issues)

    # Runtime permission check (only error, not warning)
    ac = cfg.get("actions", {})
    if isinstance(ac, dict) and not ac.get("dry_run", True):
        if os.geteuid() != 0:
            issues.append(ValidationError(
                path="actions.dry_run",
                message=(
                    "CNSL must run as root when dry_run=false "
                    "(iptables/ipset require root privileges)"
                ),
                level="error",
            ))

    return issues


def validate_and_exit(cfg: Dict[str, Any]) -> None:
    """Validate config, print errors/warnings and exit if any errors found."""
    issues = validate_config(cfg)
    errors   = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level == "warning"]

    if warnings:
        print(f"\n[CNSL] Config warnings ({len(warnings)}):\n")
        for w in warnings:
            print(f"  WARN  {w.path}: {w.message}")
        print()

    if errors:
        print(f"[CNSL] Config validation failed ({len(errors)} error(s)):\n")
        for e in errors:
            print(f"  ERROR {e.path}: {e.message}")
        print("\nFix the errors above and restart.\n")
        raise SystemExit(1)


def validate_and_print(cfg: Dict[str, Any]) -> bool:
    """
    Validate config and print a full report.
    Returns True if valid (no errors), False otherwise.
    Used by `cnsl --validate-config`.
    """
    issues = validate_config(cfg)
    errors   = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level == "warning"]

    if not issues:
        print("[CNSL] Config OK -- no errors or warnings found.")
        return True

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for w in warnings:
            print(f"  WARN  {w.path}: {w.message}")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for e in errors:
            print(f"  ERROR {e.path}: {e.message}")
        print(f"\nConfig is INVALID. Fix {len(errors)} error(s) above.\n")
        return False

    print(f"\nConfig has {len(warnings)} warning(s) but no errors.")
    return True



# Section validators


def _validate_thresholds(th: Any, issues: List) -> None:
    if not th:
        return
    if not isinstance(th, dict):
        issues.append(ValidationError("thresholds", "must be a dict"))
        return
    v = _V(th, issues, "thresholds")
    v.is_positive_int("fails_window_sec",              max_val=3600)
    v.is_positive_int("fails_threshold",               max_val=1000)
    v.is_positive_int("unique_users_threshold",        max_val=100)
    v.is_positive_int("success_after_fails_threshold", max_val=100)
    v.is_positive_int("incident_cooldown_sec",         max_val=86400)


def _validate_actions(ac: Any, issues: List) -> None:
    if not ac:
        return
    if not isinstance(ac, dict):
        issues.append(ValidationError("actions", "must be a dict"))
        return
    v = _V(ac, issues, "actions")
    v.is_bool("dry_run")
    v.is_positive_int("block_duration_sec", max_val=86400 * 30)
    v.is_one_of("block_backend", ["iptables", "ipset"])
    v.is_str("chain")


def _validate_allowlist(al: Any, issues: List) -> None:
    if not al:
        return
    if not isinstance(al, list):
        issues.append(ValidationError("allowlist", "must be a list"))
        return
    for i, entry in enumerate(al):
        try:
            ipaddress.ip_network(str(entry), strict=False)
        except ValueError:
            issues.append(ValidationError(
                f"allowlist[{i}]",
                f"invalid IP or CIDR: {entry!r}",
            ))


def _validate_store(st: Any, issues: List) -> None:
    if not st:
        return
    if not isinstance(st, dict):
        issues.append(ValidationError("store", "must be a dict"))
        return
    v = _V(st, issues, "store")
    backend = st.get("backend", "sqlite")
    v.is_one_of("backend", ["sqlite", "postgresql"])
    if backend == "postgresql":
        dsn = st.get("dsn", "")
        if not dsn or not dsn.startswith("postgresql://"):
            issues.append(ValidationError(
                "store.dsn",
                "required when backend=postgresql; must start with postgresql://",
            ))
        # Warn if asyncpg not available
        try:
            import asyncpg  # noqa: F401
        except ImportError:
            issues.append(ValidationError(
                "store.backend",
                "backend=postgresql requires asyncpg: pip install asyncpg",
                level="warning",
            ))


def _validate_logging(lg: Any, issues: List) -> None:
    if not lg or not isinstance(lg, dict):
        return
    v = _V(lg, issues, "logging")
    v.is_str("json_log_path")
    v.is_bool("console_verbose")


def _validate_auth(auth: Any, issues: List) -> None:
    if not auth or not isinstance(auth, dict):
        return
    if not auth.get("enabled"):
        return
    secret = auth.get("secret_key", "")
    if not secret:
        issues.append(ValidationError(
            "auth.secret_key",
            'required when auth.enabled=true -- generate with: '
            'python -c "import secrets; print(secrets.token_hex(32))"',
        ))
    elif len(secret) < 32:
        issues.append(ValidationError(
            "auth.secret_key",
            "must be at least 32 characters",
        ))
    elif secret in ("cnsl-secret", "change-me", "secret", "password"):
        issues.append(ValidationError(
            "auth.secret_key",
            f"insecure default value {secret!r} -- replace with a random secret",
        ))

    v = _V(auth, issues, "auth")
    sto = auth.get("session_timeout_minutes")
    if sto is not None:
        v.is_positive_int("session_timeout_minutes", max_val=10080)  # 1 week


def _validate_dashboard(dash: Any, issues: List) -> None:
    if not dash or not isinstance(dash, dict):
        return
    port = dash.get("port", 8765)
    if not isinstance(port, int) or not (1024 <= port <= 65535):
        issues.append(ValidationError(
            "dashboard.port",
            f"must be between 1024 and 65535 (got {port!r})",
        ))
    # Warn if binding to 0.0.0.0 without auth
    host = dash.get("host", "127.0.0.1")
    if host == "0.0.0.0":
        issues.append(ValidationError(
            "dashboard.host",
            "binding to 0.0.0.0 exposes the dashboard to all interfaces -- "
            "ensure auth.enabled=true or use a firewall",
            level="warning",
        ))


def _validate_notifications(notif: Any, issues: List) -> None:
    if not notif or not isinstance(notif, dict):
        return
    v = _V(notif, issues, "notifications")
    v.is_one_of("min_severity", ["HIGH", "MEDIUM", "LOW"])

    tg = notif.get("telegram", {})
    if isinstance(tg, dict) and tg.get("enabled"):
        if not tg.get("bot_token"):
            issues.append(ValidationError(
                "notifications.telegram.bot_token", "required when enabled"))
        if not tg.get("chat_id"):
            issues.append(ValidationError(
                "notifications.telegram.chat_id", "required when enabled"))

    dc = notif.get("discord", {})
    if isinstance(dc, dict) and dc.get("enabled"):
        if not dc.get("webhook_url"):
            issues.append(ValidationError(
                "notifications.discord.webhook_url", "required when enabled"))

    sl = notif.get("slack", {})
    if isinstance(sl, dict) and sl.get("enabled"):
        if not sl.get("webhook_url"):
            issues.append(ValidationError(
                "notifications.slack.webhook_url", "required when enabled"))

    em = notif.get("email", {})
    if isinstance(em, dict) and em.get("enabled"):
        for field in ("smtp_host", "username", "password"):
            if not em.get(field):
                issues.append(ValidationError(
                    f"notifications.email.{field}", "required when enabled"))
        to = em.get("to", [])
        if not to or not isinstance(to, list):
            issues.append(ValidationError(
                "notifications.email.to",
                "required: list of recipient addresses",
            ))

    dedup = notif.get("dedup_window_sec")
    if dedup is not None and (not isinstance(dedup, int) or dedup < 0):
        issues.append(ValidationError(
            "notifications.dedup_window_sec",
            "must be a non-negative integer",
        ))

    digest = notif.get("daily_digest", {})
    if isinstance(digest, dict) and digest.get("enabled"):
        h = digest.get("hour", 8)
        if not isinstance(h, int) or not (0 <= h <= 23):
            issues.append(ValidationError(
                "notifications.daily_digest.hour", "must be 0-23"))


def _validate_redis(rd: Any, issues: List) -> None:
    if not rd or not isinstance(rd, dict):
        return
    if not rd.get("enabled"):
        return
    if not rd.get("host"):
        issues.append(ValidationError("redis.host", "required when enabled"))
    port = rd.get("port", 6379)
    if not isinstance(port, int) or not (1 <= port <= 65535):
        issues.append(ValidationError(
            "redis.port", f"must be 1-65535 (got {port!r})"))
    try:
        import redis  # noqa: F401
    except ImportError:
        issues.append(ValidationError(
            "redis.enabled",
            "redis.enabled=true requires the redis package: pip install redis",
            level="warning",
        ))


def _validate_ml(ml: Any, issues: List) -> None:
    if not ml or not isinstance(ml, dict):
        return
    if not ml.get("enabled"):
        return
    v = _V(ml, issues, "ml")
    v.is_positive_int("min_samples",           max_val=100_000)
    v.is_positive_int("retrain_interval_sec",  max_val=86400 * 7)
    cont = ml.get("contamination")
    if cont is not None:
        if not isinstance(cont, (int, float)) or not (0.001 <= cont <= 0.5):
            issues.append(ValidationError(
                "ml.contamination", "must be between 0.001 and 0.5"))
    try:
        import sklearn  # noqa: F401
    except ImportError:
        issues.append(ValidationError(
            "ml.enabled",
            "ml.enabled=true requires scikit-learn: pip install scikit-learn",
            level="warning",
        ))


def _validate_kill_chain(kc: Any, issues: List) -> None:
    if not kc or not isinstance(kc, dict):
        return
    v = _V(kc, issues, "kill_chain")
    v.is_bool("enabled")
    v.is_positive_int("max_chains",    max_val=1_000_000)
    v.is_positive_int("stage_ttl_sec", max_val=86400 * 30)


def _validate_pattern_learning(pl: Any, issues: List) -> None:
    if not pl or not isinstance(pl, dict):
        return
    v = _V(pl, issues, "pattern_learning")
    v.is_bool("enabled")
    v.is_positive_int("lookback_sec",    max_val=3600)
    v.is_positive_int("min_occurrences", max_val=1000)
    v.is_positive_int("max_suggestions", max_val=10_000)


def _validate_siem(siem: Any, issues: List) -> None:
    if not siem or not isinstance(siem, dict):
        return
    for name in ("splunk", "sentinel", "webhook"):
        c = siem.get(name, {})
        if not isinstance(c, dict) or not c.get("enabled"):
            continue
        if name == "splunk":
            if not c.get("hec_url"):
                issues.append(ValidationError(
                    f"siem.splunk.hec_url", "required when enabled"))
            if not c.get("token"):
                issues.append(ValidationError(
                    f"siem.splunk.token", "required when enabled"))
        elif name == "sentinel":
            for field in ("workspace_id", "shared_key"):
                if not c.get(field):
                    issues.append(ValidationError(
                        f"siem.sentinel.{field}", "required when enabled"))
        elif name == "webhook":
            if not c.get("url"):
                issues.append(ValidationError(
                    "siem.webhook.url", "required when enabled"))


def _validate_federation(fed: Any, issues: List) -> None:
    if not fed or not isinstance(fed, dict):
        return
    if not fed.get("enabled"):
        return
    v = _V(fed, issues, "federation")
    v.is_positive_int("dedupe_window_sec", max_val=300)
    v.is_positive_int("max_remote_ips",    max_val=10_000_000)
    v.is_one_of("min_severity", ["HIGH", "MEDIUM", "LOW"])


def _validate_cloud_identity(ci: Any, issues: List) -> None:
    if not ci or not isinstance(ci, dict):
        return
    if not ci.get("enabled"):
        return
    aws = ci.get("aws", {})
    if isinstance(aws, dict) and aws.get("enabled"):
        if not aws.get("access_key_id"):
            issues.append(ValidationError(
                "cloud_identity.aws.access_key_id", "required when enabled"))
        if not aws.get("secret_access_key"):
            issues.append(ValidationError(
                "cloud_identity.aws.secret_access_key", "required when enabled"))
        region = aws.get("region", "")
        if region and not region.startswith(("us-", "eu-", "ap-", "ca-",
                                             "sa-", "af-", "me-")):
            issues.append(ValidationError(
                "cloud_identity.aws.region",
                f"unrecognized AWS region format: {region!r}",
                level="warning",
            ))

    az = ci.get("azure_ad", {})
    if isinstance(az, dict) and az.get("enabled"):
        for field in ("tenant_id", "client_id", "client_secret"):
            if not az.get(field):
                issues.append(ValidationError(
                    f"cloud_identity.azure_ad.{field}", "required when enabled"))


def _validate_zero_trust(zt: Any, issues: List) -> None:
    if not zt or not isinstance(zt, dict):
        return
    init_score = zt.get("initial_score")
    if init_score is not None:
        if not isinstance(init_score, (int, float)) or not (0.0 < init_score <= 1.0):
            issues.append(ValidationError(
                "zero_trust.initial_score", "must be between 0.0 and 1.0"))
    min_score = zt.get("min_score")
    if min_score is not None:
        if not isinstance(min_score, (int, float)) or not (0.0 <= min_score < 1.0):
            issues.append(ValidationError(
                "zero_trust.min_score", "must be between 0.0 and 1.0"))
    rec = zt.get("recovery_per_day")
    if rec is not None:
        if not isinstance(rec, (int, float)) or rec <= 0:
            issues.append(ValidationError(
                "zero_trust.recovery_per_day", "must be > 0"))


def _validate_ot(ot: Any, issues: List) -> None:
    if not ot or not isinstance(ot, dict):
        return
    if not ot.get("enabled"):
        return
    sources = ot.get("log_sources", {})
    if not isinstance(sources, dict):
        issues.append(ValidationError(
            "ot.log_sources", "must be a dict of protocol->path"))
        return
    valid_protocols = {"modbus", "dnp3", "scada"}
    for proto, path in sources.items():
        if proto not in valid_protocols:
            issues.append(ValidationError(
                f"ot.log_sources.{proto}",
                f"unknown OT protocol {proto!r}; valid: {sorted(valid_protocols)}",
                level="warning",
            ))
        if path and not isinstance(path, str):
            issues.append(ValidationError(
                f"ot.log_sources.{proto}", "path must be a string"))
    trusted = ot.get("trusted_ips", [])
    if isinstance(trusted, list):
        for i, ip in enumerate(trusted):
            try:
                ipaddress.ip_address(str(ip))
            except ValueError:
                issues.append(ValidationError(
                    f"ot.trusted_ips[{i}]",
                    f"invalid IP address: {ip!r}",
                ))


def _validate_rules(rules: Any, issues: List) -> None:
    if not rules or not isinstance(rules, dict):
        return
    KNOWN_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}
    for rule_id, overrides in rules.items():
        if not isinstance(overrides, dict):
            issues.append(ValidationError(
                f"rules.{rule_id}", "must be a dict"))
            continue
        sev = overrides.get("severity")
        if sev is not None and sev not in KNOWN_SEVERITIES:
            issues.append(ValidationError(
                f"rules.{rule_id}.severity",
                f"must be HIGH, MEDIUM, or LOW (got {sev!r})",
            ))
        thresh = overrides.get("threshold")
        if thresh is not None:
            if not isinstance(thresh, int) or thresh < 1:
                issues.append(ValidationError(
                    f"rules.{rule_id}.threshold",
                    f"must be a positive integer (got {thresh!r})",
                ))
        window = overrides.get("window_sec")
        if window is not None:
            if not isinstance(window, int) or window < 0:
                issues.append(ValidationError(
                    f"rules.{rule_id}.window_sec",
                    f"must be a non-negative integer (got {window!r})",
                ))



# Internal helper


class _V:
    """Lightweight validator helper for one config sub-dict."""

    def __init__(self, d: Dict, issues: List, prefix: str = ""):
        self._d      = d
        self._issues = issues
        self._prefix = prefix

    def _key(self, k: str) -> str:
        return f"{self._prefix}.{k}" if self._prefix else k

    def is_str(self, key: str, required: bool = False) -> None:
        val = self._d.get(key)
        if val is None:
            if required:
                self._issues.append(ValidationError(
                    self._key(key), "required"))
            return
        if not isinstance(val, str):
            self._issues.append(ValidationError(
                self._key(key),
                f"must be a string (got {type(val).__name__})"))
        elif required and not val.strip():
            self._issues.append(ValidationError(
                self._key(key), "must not be empty"))

    def is_bool(self, key: str) -> None:
        val = self._d.get(key)
        if val is not None and not isinstance(val, bool):
            self._issues.append(ValidationError(
                self._key(key),
                f"must be true or false (got {val!r})"))

    def is_positive_int(self, key: str, max_val: int = 1_000_000) -> None:
        val = self._d.get(key)
        if val is None:
            return
        if not isinstance(val, int) or isinstance(val, bool):
            self._issues.append(ValidationError(
                self._key(key),
                f"must be an integer (got {val!r})"))
            return
        if val <= 0:
            self._issues.append(ValidationError(
                self._key(key), f"must be > 0 (got {val})"))
        elif val > max_val:
            self._issues.append(ValidationError(
                self._key(key), f"must be <= {max_val} (got {val})"))

    def is_one_of(self, key: str, choices: list) -> None:
        val = self._d.get(key)
        if val is not None and val not in choices:
            self._issues.append(ValidationError(
                self._key(key),
                f"must be one of {choices} (got {val!r})"))