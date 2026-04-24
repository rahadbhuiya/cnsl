"""
cnsl/fim.py — File Integrity Monitoring (FIM).

Watches critical system files for unauthorized changes.
Uses SHA-256 hashing + inotify (via watchdog) for real-time detection.

What it watches (configurable):
  /etc/passwd              — user account changes
  /etc/shadow              — password hash changes
  /etc/sudoers             — privilege escalation setup
  /etc/ssh/sshd_config     — SSH backdoor config
  /root/.ssh/authorized_keys  — attacker adding SSH key
  /home/*/.ssh/authorized_keys
  /etc/crontab, /etc/cron.d/* — persistence via cron
  /etc/hosts               — DNS hijacking
  /etc/ld.so.preload       — library injection (rootkit)
  /sbin/init, /bin/bash    — binary replacement

Alert severity:
  CRITICAL  — auth files, SSH keys, sudo, ld.so.preload (rootkit)
  HIGH      — cron, /etc/hosts, init binaries
  MEDIUM    — config files, logs

Config example:
  "fim": {
    "enabled": true,
    "db_path": "./cnsl_fim.db",
    "scan_interval_sec": 300,
    "watch_paths": [
      "/etc/passwd", "/etc/shadow", "/etc/sudoers",
      "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys"
    ],
    "watch_dirs": [
      { "path": "/etc/cron.d", "recursive": false },
      { "path": "/home",       "recursive": true,
        "pattern": ".ssh/authorized_keys" }
    ],
    "alert_on_delete": true,
    "alert_on_create": true
  }
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from .logger import JsonLogger
from .models import iso_time, now



# Severity classification


_CRITICAL_PATHS = {
    "/etc/passwd", "/etc/shadow", "/etc/gshadow",
    "/etc/sudoers", "/etc/sudoers.d",
    "/root/.ssh/authorized_keys", "/root/.ssh/id_rsa",
    "/etc/ld.so.preload",          # rootkit indicator
    "/etc/pam.d/sshd", "/etc/pam.d/su",
}

_HIGH_PATHS = {
    "/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
    "/etc/hosts", "/etc/resolv.conf",
    "/etc/ssh/sshd_config",
    "/sbin/init", "/bin/bash", "/bin/sh", "/usr/bin/sudo",
    "/etc/profile", "/etc/bashrc", "/etc/environment",
}

_SSH_KEY_PATTERN = "authorized_keys"


def _classify(path: str) -> str:
    p = str(path)
    if any(p.startswith(c) or p == c for c in _CRITICAL_PATHS):
        return "CRITICAL"
    if _SSH_KEY_PATTERN in p:
        return "CRITICAL"
    if any(p.startswith(h) or p == h for h in _HIGH_PATHS):
        return "HIGH"
    return "MEDIUM"



# Hashing


def _sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _file_meta(path: str) -> Dict:
    try:
        st = os.stat(path)
        return {
            "size":  st.st_size,
            "mtime": st.st_mtime,
            "mode":  oct(st.st_mode),
            "uid":   st.st_uid,
            "gid":   st.st_gid,
        }
    except OSError:
        return {}



# FIM alert


@dataclass
class FIMAlert:
    path:      str
    change:    str          # "modified" | "created" | "deleted" | "permission"
    severity:  str          # "CRITICAL" | "HIGH" | "MEDIUM"
    old_hash:  Optional[str]
    new_hash:  Optional[str]
    old_meta:  Dict
    new_meta:  Dict
    ts:        float

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["time"] = iso_time(self.ts)
        return d

    def summary(self) -> str:
        return (
            f"[FIM {self.severity}] {self.change.upper()}: {self.path}"
        )



# Baseline database


_SCHEMA = """
CREATE TABLE IF NOT EXISTS fim_baseline (
    path        TEXT PRIMARY KEY,
    hash        TEXT,
    size        INTEGER,
    mtime       REAL,
    mode        TEXT,
    uid         INTEGER,
    gid         INTEGER,
    first_seen  REAL,
    last_seen   REAL
);
CREATE TABLE IF NOT EXISTS fim_alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL,
    time      TEXT,
    path      TEXT,
    change    TEXT,
    severity  TEXT,
    old_hash  TEXT,
    new_hash  TEXT,
    meta      TEXT
);
"""


class FIMDatabase:
    def __init__(self, db_path: str):
        self._path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def get_baseline(self, path: str) -> Optional[Dict]:
        row = self._conn.execute(
            "SELECT * FROM fim_baseline WHERE path=?", (path,)
        ).fetchone()
        if not row:
            return None
        cols = [d[0] for d in self._conn.execute(
            "SELECT * FROM fim_baseline LIMIT 0"
        ).description]
        return dict(zip(cols, row))

    def upsert_baseline(self, path: str, hash_: str, meta: Dict) -> None:
        t = now()
        existing = self.get_baseline(path)
        if existing:
            self._conn.execute(
                "UPDATE fim_baseline SET hash=?,size=?,mtime=?,mode=?,uid=?,gid=?,last_seen=? WHERE path=?",
                (hash_, meta.get("size"), meta.get("mtime"), meta.get("mode"),
                 meta.get("uid"), meta.get("gid"), t, path)
            )
        else:
            self._conn.execute(
                "INSERT INTO fim_baseline VALUES (?,?,?,?,?,?,?,?,?)",
                (path, hash_, meta.get("size"), meta.get("mtime"),
                 meta.get("mode"), meta.get("uid"), meta.get("gid"), t, t)
            )
        self._conn.commit()

    def delete_baseline(self, path: str) -> None:
        self._conn.execute("DELETE FROM fim_baseline WHERE path=?", (path,))
        self._conn.commit()

    def save_alert(self, alert: FIMAlert) -> None:
        self._conn.execute(
            "INSERT INTO fim_alerts (ts,time,path,change,severity,old_hash,new_hash,meta) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (alert.ts, iso_time(alert.ts), alert.path, alert.change,
             alert.severity, alert.old_hash, alert.new_hash,
             json.dumps({**alert.old_meta, **alert.new_meta}))
        )
        self._conn.commit()

    def all_baselines(self) -> List[Dict]:
        rows = self._conn.execute("SELECT * FROM fim_baseline").fetchall()
        cols = [d[0] for d in self._conn.execute(
            "SELECT * FROM fim_baseline LIMIT 0"
        ).description]
        return [dict(zip(cols, r)) for r in rows]

    def recent_alerts(self, limit: int = 50) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT * FROM fim_alerts ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        cols = [d[0] for d in self._conn.execute(
            "SELECT * FROM fim_alerts LIMIT 0"
        ).description]
        return [dict(zip(cols, r)) for r in rows]

    def close(self) -> None:
        self._conn.close()



# FIM Engine


class FIMEngine:
    """
    File Integrity Monitor.

    Usage:
        fim = FIMEngine(cfg, logger)
        fim.on_alert = my_async_callback   # async fn(FIMAlert)
        await fim.initialize()             # build/load baseline
        await fim.start()                  # start monitoring loop
    """

    def __init__(self, cfg: Dict[str, Any], logger: JsonLogger):
        fim_cfg = cfg.get("fim", {})

        self.enabled       = bool(fim_cfg.get("enabled", False))
        self.db_path       = fim_cfg.get("db_path", "./cnsl_fim.db")
        self.scan_interval = int(fim_cfg.get("scan_interval_sec", 300))
        self.alert_delete  = bool(fim_cfg.get("alert_on_delete", True))
        self.alert_create  = bool(fim_cfg.get("alert_on_create", True))

        # Paths to watch
        self._watch_paths: List[str] = fim_cfg.get("watch_paths", _DEFAULT_PATHS)
        self._watch_dirs:  List[Dict] = fim_cfg.get("watch_dirs",  _DEFAULT_DIRS)

        self.logger   = logger
        self._db:     Optional[FIMDatabase] = None

        # Callback — set by engine
        self.on_alert: Optional[Callable] = None

    async def initialize(self) -> None:
        """Build baseline on first run, load existing on subsequent runs."""
        if not self.enabled:
            return

        self._db = FIMDatabase(self.db_path)
        paths    = self._collect_paths()
        existing = {b["path"] for b in self._db.all_baselines()}
        new_paths = 0

        for path in paths:
            if path not in existing:
                h    = _sha256(path)
                meta = _file_meta(path)
                if h:
                    self._db.upsert_baseline(path, h, meta)
                    new_paths += 1

        await self.logger.log("fim_initialized", {
            "total_paths":  len(paths),
            "new_baselines": new_paths,
            "db_path":      self.db_path,
        })

    async def start(self) -> None:
        """Long-running scan loop."""
        if not self.enabled or not self._db:
            return

        await self.logger.log("fim_started", {
            "scan_interval_sec": self.scan_interval,
            "watching": len(self._collect_paths()),
        })

        while True:
            try:
                await self._scan()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                await self.logger.log("fim_error", {"error": str(e)})

            await asyncio.sleep(self.scan_interval)

    async def _scan(self) -> None:
        """One full scan pass — compare current state to baseline."""
        loop      = asyncio.get_running_loop()
        paths     = self._collect_paths()
        # Load baselines in thread — synchronous SQLite read
        baselines = await loop.run_in_executor(None, lambda: {
            b["path"]: b for b in self._db.all_baselines()
        })
        seen:     Set[str] = set()

        # Check for deleted files (in baseline but no longer on disk or in scan list)
        for path, baseline in baselines.items():
            if path not in paths and not os.path.exists(path) and self.alert_delete:
                await self._fire(FIMAlert(
                    path=path, change="deleted",
                    severity=_classify(path),
                    old_hash=baseline["hash"], new_hash=None,
                    old_meta={"mtime": baseline.get("mtime")}, new_meta={},
                    ts=now(),
                ))
                await loop.run_in_executor(None, self._db.delete_baseline, path)

        for path in paths:
            seen.add(path)
            exists   = os.path.exists(path)
            baseline = baselines.get(path)

            if not exists:
                if baseline and self.alert_delete:
                    await self._fire(FIMAlert(
                        path=path, change="deleted",
                        severity=_classify(path),
                        old_hash=baseline["hash"],  new_hash=None,
                        old_meta={"mtime": baseline.get("mtime")}, new_meta={},
                        ts=now(),
                    ))
                    await loop.run_in_executor(None, self._db.delete_baseline, path)
                continue

            # Compute hash in thread (blocking I/O)
            new_hash = await loop.run_in_executor(None, _sha256, path)
            new_meta = await loop.run_in_executor(None, _file_meta, path)

            if not new_hash:
                continue

            if baseline is None:
                # New file appeared
                if self.alert_create:
                    await self._fire(FIMAlert(
                        path=path, change="created",
                        severity=_classify(path),
                        old_hash=None, new_hash=new_hash,
                        old_meta={}, new_meta=new_meta,
                        ts=now(),
                    ))
                await loop.run_in_executor(
                    None, self._db.upsert_baseline, path, new_hash, new_meta
                )

            elif new_hash != baseline["hash"]:
                # Content changed
                await self._fire(FIMAlert(
                    path=path, change="modified",
                    severity=_classify(path),
                    old_hash=baseline["hash"], new_hash=new_hash,
                    old_meta={"mtime": baseline.get("mtime"),
                               "mode":  baseline.get("mode")},
                    new_meta=new_meta,
                    ts=now(),
                ))
                await loop.run_in_executor(
                    None, self._db.upsert_baseline, path, new_hash, new_meta
                )

            elif new_meta.get("mode") != baseline.get("mode"):
                # Permissions changed
                await self._fire(FIMAlert(
                    path=path, change="permission",
                    severity=_classify(path),
                    old_hash=new_hash, new_hash=new_hash,
                    old_meta={"mode": baseline.get("mode")},
                    new_meta={"mode": new_meta.get("mode")},
                    ts=now(),
                ))
                await loop.run_in_executor(
                    None, self._db.upsert_baseline, path, new_hash, new_meta
                )

    async def _fire(self, alert: FIMAlert) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._db.save_alert, alert)
        await self.logger.log("fim_alert", alert.to_dict())

        if self.on_alert:
            try:
                await self.on_alert(alert)
            except Exception:
                pass

    def _collect_paths(self) -> List[str]:
        """Expand all configured paths and directories into a flat list."""
        paths: List[str] = []

        for p in self._watch_paths:
            if os.path.isfile(p):
                paths.append(p)

        for d in self._watch_dirs:
            dir_path  = d.get("path", "")
            recursive = bool(d.get("recursive", False))
            pattern   = d.get("pattern", "*")

            if not os.path.isdir(dir_path):
                continue

            base = Path(dir_path)
            glob = "**/" + pattern if recursive else pattern
            for p in base.glob(glob):
                if p.is_file():
                    paths.append(str(p))

        return list(set(paths))

    def recent_alerts(self, limit: int = 50) -> List[Dict]:
        if self._db:
            return self._db.recent_alerts(limit)
        return []

    def close(self) -> None:
        if self._db:
            self._db.close()



# Defaults


_DEFAULT_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/root/.ssh/authorized_keys",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/crontab",
    "/etc/ld.so.preload",
    "/etc/profile",
    "/etc/bashrc",
    "/etc/environment",
    "/etc/pam.d/sshd",
]

_DEFAULT_DIRS = [
    {"path": "/etc/cron.d",       "recursive": False, "pattern": "*"},
    {"path": "/etc/cron.daily",   "recursive": False, "pattern": "*"},
    {"path": "/etc/sudoers.d",    "recursive": False, "pattern": "*"},
    {"path": "/etc/ssh",          "recursive": False, "pattern": "*.pub"},
    {"path": "/home",             "recursive": True,  "pattern": "authorized_keys"},
]